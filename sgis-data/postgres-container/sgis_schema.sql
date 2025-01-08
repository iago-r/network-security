--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

--
-- Name: get_org_ancestors(integer); Type: FUNCTION; Schema: public; Owner: sgis
--

CREATE FUNCTION get_org_ancestors(org_id integer) RETURNS integer[]
    LANGUAGE plpgsql
    AS $$
DECLARE

    org_tree_id integer;
    org_lft integer;
    org_rght integer;
    ret integer[];

BEGIN

    SELECT tree_id, lft, rght INTO org_tree_id, org_lft, org_rght
    FROM organization_organization
    WHERE organization_organization.id = org_id;

    SELECT ARRAY(
        SELECT organization_organization.id
        FROM organization_organization
        WHERE organization_organization.lft <= org_lft AND
              organization_organization.rght >= org_rght AND
              organization_organization.tree_id = org_tree_id
        ORDER BY organization_organization.id
    ) INTO ret;

    RETURN ret;

END;
$$;


ALTER FUNCTION public.get_org_ancestors(org_id integer) OWNER TO sgis;

--
-- Name: get_org_descendants(integer); Type: FUNCTION; Schema: public; Owner: sgis
--

CREATE FUNCTION get_org_descendants(org_id integer) RETURNS integer[]
    LANGUAGE plpgsql
    AS $$
DECLARE

    org_tree_id integer;
    org_lft integer;
    org_rght integer;
    ret integer[];

BEGIN

    SELECT tree_id, lft, rght INTO org_tree_id, org_lft, org_rght
    FROM organization_organization
    WHERE organization_organization.id = org_id;

    SELECT ARRAY(
        SELECT organization_organization.id
        FROM organization_organization
        WHERE organization_organization.lft >= org_lft AND
              organization_organization.lft <= org_rght AND
              organization_organization.tree_id = org_tree_id
        ORDER BY organization_organization.id
    ) INTO ret;

    RETURN ret;

END;
$$;


ALTER FUNCTION public.get_org_descendants(org_id integer) OWNER TO sgis;

--
-- Name: get_org_descendants(integer, integer); Type: FUNCTION; Schema: public; Owner: sgis
--

CREATE FUNCTION get_org_descendants(org_id integer, level_delta integer) RETURNS integer[]
    LANGUAGE plpgsql
    AS $$
DECLARE

    org_tree_id integer;
    org_lft integer;
    org_rght integer;
    org_level integer;
    ret integer[];

BEGIN

    SELECT tree_id, lft, rght, level
    INTO org_tree_id, org_lft, org_rght, org_level
    FROM organization_organization
    WHERE organization_organization.id = org_id;

    SELECT ARRAY(
        SELECT organization_organization.id
        FROM organization_organization
        WHERE organization_organization.lft >= org_lft AND
              organization_organization.lft <= org_rght AND
              organization_organization.level >= org_level AND
	      organization_organization.level <= (org_level + level_delta) AND
              organization_organization.tree_id = org_tree_id
        ORDER BY organization_organization.id
    ) INTO ret;

    RETURN ret;

END;
$$;


ALTER FUNCTION public.get_org_descendants(org_id integer, level_delta integer) OWNER TO sgis;

--
-- Name: update_incident_summary(); Type: FUNCTION; Schema: public; Owner: sgis
--

CREATE FUNCTION update_incident_summary() RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE

    sd timestamp;
    min_date timestamp := NULL;

BEGIN

    SELECT MIN(created) INTO min_date FROM incident_incident;

    FOR sd IN SELECT generate_series(min_date - '1 year'::interval,
                                     NOW() + '1 month'::interval,
                                     '1 month'::interval)
    LOOP
        PERFORM update_incident_summary(sd);
    END LOOP;

END;
$$;


ALTER FUNCTION public.update_incident_summary() OWNER TO sgis;

--
-- Name: update_incident_summary(timestamp without time zone); Type: FUNCTION; Schema: public; Owner: sgis
--

CREATE FUNCTION update_incident_summary(sd timestamp without time zone) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE

    org_id integer;

BEGIN

    FOR org_id IN SELECT id FROM organization_organization
    LOOP
        PERFORM update_incident_summary(sd, org_id, false);
        PERFORM update_incident_summary(sd, org_id, true);
    END LOOP;

END;
$$;


ALTER FUNCTION public.update_incident_summary(sd timestamp without time zone) OWNER TO sgis;

--
-- Name: update_incident_summary(timestamp without time zone, integer, boolean); Type: FUNCTION; Schema: public; Owner: sgis
--

CREATE FUNCTION update_incident_summary(sd timestamp without time zone, org_id integer, vul boolean) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE

    opened_ integer;
    closed_ integer;
    missing_ integer;
    attacks_opened_ integer;
    closed_avg_ numeric(20, 2);
    missing_avg_ numeric(20, 2);
    score_ numeric(20, 2);
    start_date date;
    end_date date;
    new_summary boolean;

BEGIN

    -- sd can be any date as this will get the first and last days of the month
    start_date := DATE(date_trunc('month', sd));
    end_date := DATE(start_date + '1 month'::interval);

    SELECT COALESCE(SUM(counts.opened), 0), COALESCE(SUM(counts.closed), 0),
           COALESCE(SUM(counts.missing), 0),
           COALESCE(SUM(counts.attacks_opened), 0),
           AVG(counts.closed_avg), AVG(counts.missing_avg),
           CASE
           WHEN (SUM(counts.opened) IS NULL AND
                 SUM(counts.closed) IS NULL AND
                 SUM(counts.missing) IS NULL) THEN 0
           ELSE ((COALESCE(SUM(counts.opened), 1)::float /
                  COALESCE(SUM(counts.closed), 1)::float) *
                 (COALESCE(AVG(counts.closed_avg), 1) * COALESCE(SUM(counts.closed), 1) +
                  COALESCE(AVG(counts.missing_avg), 1)) * COALESCE(SUM(counts.missing), 1) /
                 (COALESCE(SUM(counts.closed), 1)::float + COALESCE(SUM(counts.missing), 1)::float))
           END

           INTO opened_, closed_, missing_, attacks_opened_, closed_avg_, missing_avg_, score_

    FROM (

        SELECT organizations.oid AS oid, opened.count AS opened,
               closed.count AS closed, closed.avg AS closed_avg,
               missing.count AS missing, missing.avg AS missing_avg,
               attacks_opened.count AS attacks_opened

        FROM
            (SELECT unnest(get_org_descendants(org_id)) AS oid) AS organizations

        LEFT JOIN
            (SELECT organization_id AS oid, COUNT(1) AS count
             FROM incident_incident
             WHERE notified BETWEEN start_date AND end_date AND
                   vulnerability = vul
             GROUP BY oid) AS opened
        ON opened.oid = organizations.oid

        LEFT JOIN
            (SELECT organization_id AS oid, COUNT(1) AS count,
                    EXTRACT(epoch FROM AVG(resolved - notified)) / 3600 AS avg
             FROM incident_incident
             WHERE resolved BETWEEN start_date AND end_date AND
                   vulnerability = vul
             GROUP BY oid) AS closed
        ON closed.oid = organizations.oid

        LEFT JOIN
            (SELECT organization_id AS oid, COUNT(1) AS count,
                    EXTRACT(epoch FROM AVG(end_date - notified)) / 3600 AS avg
             FROM incident_incident
             WHERE notified < end_date AND
                   (resolved IS NULL OR resolved > end_date) AND
                   vulnerability = vul
             GROUP BY oid) AS missing
        ON missing.oid = organizations.oid

        LEFT JOIN
            (SELECT organization_id AS oid, COUNT(1) AS count
             FROM incident_attack
             WHERE created BETWEEN start_date AND end_date
             GROUP BY oid) AS attacks_opened
        ON attacks_opened.oid = organizations.oid

    ) AS counts;

    -- First, try to update the existing row
    UPDATE incident_summary
    SET last_update = NOW(), opened = opened_, closed = closed_, missing = missing_,
        closed_avg = closed_avg_, missing_avg = missing_avg_, score = score_,
        attacks_opened = attacks_opened_
    WHERE organization_id = org_id AND summary_date = start_date AND vulnerability = vul;
    -- If no row for the given org_id, summary_date pair, insert one
    IF NOT FOUND THEN
        INSERT INTO incident_summary
            (organization_id, summary_date, last_update, vulnerability,
	     opened, closed, missing, closed_avg, missing_avg, attacks_opened,
             score)
        VALUES
            (org_id, start_date, NOW(), vul, opened_, closed_,
             missing_, closed_avg_, missing_avg_, attacks_opened_, score_);

        new_summary := true;
    ELSE
        new_summary := false;
    END IF;

    PERFORM update_incident_summary_users(sd, org_id);
END;
$$;


ALTER FUNCTION public.update_incident_summary(sd timestamp without time zone, org_id integer, vul boolean) OWNER TO sgis;

--
-- Name: update_incident_summary_users(timestamp without time zone, integer); Type: FUNCTION; Schema: public; Owner: sgis
--

CREATE FUNCTION update_incident_summary_users(sd timestamp without time zone, org_id integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE

    org_permission RECORD;
    start_date date;
    end_date date;

BEGIN

    -- sd can be any date as this will get the first and last days of the month
    start_date := DATE(date_trunc('month', sd));
    end_date := DATE(start_date + '1 month'::interval);

    FOR org_permission IN
            SELECT * FROM organization_permission
            WHERE organization_id = org_id AND
                  DATE(created) < end_date LOOP
        -- First try to update the record for that user in that month
        UPDATE incident_summary_users
            SET permission = org_permission.permission
            WHERE summary_date = start_date AND
                  organization_id = org_id AND
                  user_id = org_permission.user_id;
        -- If it doesn't exist, insert a new one
        IF NOT FOUND THEN
            INSERT INTO incident_summary_users
                (summary_date, organization_id, user_id, permission)
            VALUES
                (start_date, org_id,
                 org_permission.user_id, org_permission.permission);
        END IF;
    END LOOP;

END;
$$;


ALTER FUNCTION public.update_incident_summary_users(sd timestamp without time zone, org_id integer) OWNER TO sgis;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: account_profile; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE account_profile (
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    user_id integer NOT NULL,
    creator_id integer NOT NULL,
    home_id integer,
    phone character varying(20),
    mobile character varying(20),
    voip character varying(50),
    pgp character varying(50),
    notes text,
    language character varying(10),
    function integer NOT NULL,
    expires timestamp with time zone,
    cafe_auth boolean NOT NULL
);


ALTER TABLE public.account_profile OWNER TO sgis;

--
-- Name: actstream_action; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE actstream_action (
    id integer NOT NULL,
    actor_content_type_id integer NOT NULL,
    actor_object_id character varying(255) NOT NULL,
    verb character varying(255) NOT NULL,
    description text,
    target_content_type_id integer,
    target_object_id character varying(255),
    action_object_content_type_id integer,
    action_object_object_id character varying(255),
    "timestamp" timestamp with time zone NOT NULL,
    public boolean NOT NULL,
    data text
);


ALTER TABLE public.actstream_action OWNER TO sgis;

--
-- Name: actstream_action_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE actstream_action_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.actstream_action_id_seq OWNER TO sgis;

--
-- Name: actstream_action_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE actstream_action_id_seq OWNED BY actstream_action.id;


--
-- Name: actstream_follow; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE actstream_follow (
    id integer NOT NULL,
    user_id integer NOT NULL,
    content_type_id integer NOT NULL,
    object_id character varying(255) NOT NULL,
    actor_only boolean NOT NULL,
    started timestamp with time zone NOT NULL
);


ALTER TABLE public.actstream_follow OWNER TO sgis;

--
-- Name: actstream_follow_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE actstream_follow_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.actstream_follow_id_seq OWNER TO sgis;

--
-- Name: actstream_follow_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE actstream_follow_id_seq OWNED BY actstream_follow.id;


--
-- Name: aggregation_rememberconfig; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE aggregation_rememberconfig (
    id integer NOT NULL,
    "interval" integer NOT NULL
);


ALTER TABLE public.aggregation_rememberconfig OWNER TO sgis;

--
-- Name: aggregation_rememberconfig_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE aggregation_rememberconfig_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.aggregation_rememberconfig_id_seq OWNER TO sgis;

--
-- Name: aggregation_rememberconfig_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE aggregation_rememberconfig_id_seq OWNED BY aggregation_rememberconfig.id;


--
-- Name: attachments_attachment; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE attachments_attachment (
    reusableplugin_ptr_id integer NOT NULL,
    current_revision_id integer,
    original_filename character varying(256)
);


ALTER TABLE public.attachments_attachment OWNER TO sgis;

--
-- Name: attachments_attachmentrevision; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE attachments_attachmentrevision (
    id integer NOT NULL,
    revision_number integer NOT NULL,
    user_message text NOT NULL,
    automatic_log text NOT NULL,
    ip_address inet,
    user_id integer,
    modified timestamp with time zone NOT NULL,
    created timestamp with time zone NOT NULL,
    previous_revision_id integer,
    deleted boolean NOT NULL,
    locked boolean NOT NULL,
    attachment_id integer NOT NULL,
    file character varying(100) NOT NULL,
    description text NOT NULL
);


ALTER TABLE public.attachments_attachmentrevision OWNER TO sgis;

--
-- Name: attachments_attachmentrevision_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE attachments_attachmentrevision_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.attachments_attachmentrevision_id_seq OWNER TO sgis;

--
-- Name: attachments_attachmentrevision_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE attachments_attachmentrevision_id_seq OWNED BY attachments_attachmentrevision.id;


--
-- Name: auth_group; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE auth_group (
    id integer NOT NULL,
    name character varying(80) NOT NULL
);


ALTER TABLE public.auth_group OWNER TO sgis;

--
-- Name: auth_group_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE auth_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_group_id_seq OWNER TO sgis;

--
-- Name: auth_group_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE auth_group_id_seq OWNED BY auth_group.id;


--
-- Name: auth_group_permissions; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE auth_group_permissions (
    id integer NOT NULL,
    group_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.auth_group_permissions OWNER TO sgis;

--
-- Name: auth_group_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE auth_group_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_group_permissions_id_seq OWNER TO sgis;

--
-- Name: auth_group_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE auth_group_permissions_id_seq OWNED BY auth_group_permissions.id;


--
-- Name: auth_permission; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE auth_permission (
    id integer NOT NULL,
    name character varying(50) NOT NULL,
    content_type_id integer NOT NULL,
    codename character varying(100) NOT NULL
);


ALTER TABLE public.auth_permission OWNER TO sgis;

--
-- Name: auth_permission_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE auth_permission_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_permission_id_seq OWNER TO sgis;

--
-- Name: auth_permission_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE auth_permission_id_seq OWNED BY auth_permission.id;


--
-- Name: auth_user; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE auth_user (
    id integer NOT NULL,
    password character varying(128) NOT NULL,
    last_login timestamp with time zone NOT NULL,
    is_superuser boolean NOT NULL,
    username character varying(30) NOT NULL,
    first_name character varying(30) NOT NULL,
    last_name character varying(30) NOT NULL,
    email character varying(75) NOT NULL,
    is_staff boolean NOT NULL,
    is_active boolean NOT NULL,
    date_joined timestamp with time zone NOT NULL
);


ALTER TABLE public.auth_user OWNER TO sgis;

--
-- Name: auth_user_groups; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE auth_user_groups (
    id integer NOT NULL,
    user_id integer NOT NULL,
    group_id integer NOT NULL
);


ALTER TABLE public.auth_user_groups OWNER TO sgis;

--
-- Name: auth_user_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE auth_user_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_user_groups_id_seq OWNER TO sgis;

--
-- Name: auth_user_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE auth_user_groups_id_seq OWNED BY auth_user_groups.id;


--
-- Name: auth_user_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE auth_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_user_id_seq OWNER TO sgis;

--
-- Name: auth_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE auth_user_id_seq OWNED BY auth_user.id;


--
-- Name: auth_user_user_permissions; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE auth_user_user_permissions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.auth_user_user_permissions OWNER TO sgis;

--
-- Name: auth_user_user_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE auth_user_user_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_user_user_permissions_id_seq OWNER TO sgis;

--
-- Name: auth_user_user_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE auth_user_user_permissions_id_seq OWNED BY auth_user_user_permissions.id;


--
-- Name: celery_taskmeta; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE celery_taskmeta (
    id integer NOT NULL,
    task_id character varying(255) NOT NULL,
    status character varying(50) NOT NULL,
    result text,
    date_done timestamp with time zone NOT NULL,
    traceback text,
    hidden boolean NOT NULL,
    meta text
);


ALTER TABLE public.celery_taskmeta OWNER TO sgis;

--
-- Name: celery_taskmeta_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE celery_taskmeta_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.celery_taskmeta_id_seq OWNER TO sgis;

--
-- Name: celery_taskmeta_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE celery_taskmeta_id_seq OWNED BY celery_taskmeta.id;


--
-- Name: celery_tasksetmeta; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE celery_tasksetmeta (
    id integer NOT NULL,
    taskset_id character varying(255) NOT NULL,
    result text NOT NULL,
    date_done timestamp with time zone NOT NULL,
    hidden boolean NOT NULL
);


ALTER TABLE public.celery_tasksetmeta OWNER TO sgis;

--
-- Name: celery_tasksetmeta_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE celery_tasksetmeta_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.celery_tasksetmeta_id_seq OWNER TO sgis;

--
-- Name: celery_tasksetmeta_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE celery_tasksetmeta_id_seq OWNED BY celery_tasksetmeta.id;


--
-- Name: contact_contact; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE contact_contact (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    slug character varying(50) NOT NULL,
    name character varying(254) NOT NULL,
    email character varying(254) NOT NULL,
    phone character varying(20) NOT NULL,
    creator_id integer NOT NULL
);


ALTER TABLE public.contact_contact OWNER TO sgis;

--
-- Name: contact_contact_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE contact_contact_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.contact_contact_id_seq OWNER TO sgis;

--
-- Name: contact_contact_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE contact_contact_id_seq OWNED BY contact_contact.id;


--
-- Name: contact_contact_organizations; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE contact_contact_organizations (
    id integer NOT NULL,
    contact_id integer NOT NULL,
    organization_id integer NOT NULL
);


ALTER TABLE public.contact_contact_organizations OWNER TO sgis;

--
-- Name: contact_contact_organizations_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE contact_contact_organizations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.contact_contact_organizations_id_seq OWNER TO sgis;

--
-- Name: contact_contact_organizations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE contact_contact_organizations_id_seq OWNED BY contact_contact_organizations.id;


--
-- Name: django_admin_log; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE django_admin_log (
    id integer NOT NULL,
    action_time timestamp with time zone NOT NULL,
    user_id integer NOT NULL,
    content_type_id integer,
    object_id text,
    object_repr character varying(200) NOT NULL,
    action_flag smallint NOT NULL,
    change_message text NOT NULL,
    CONSTRAINT django_admin_log_action_flag_check CHECK ((action_flag >= 0))
);


ALTER TABLE public.django_admin_log OWNER TO sgis;

--
-- Name: django_admin_log_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE django_admin_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.django_admin_log_id_seq OWNER TO sgis;

--
-- Name: django_admin_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE django_admin_log_id_seq OWNED BY django_admin_log.id;


--
-- Name: django_content_type; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE django_content_type (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    app_label character varying(100) NOT NULL,
    model character varying(100) NOT NULL
);


ALTER TABLE public.django_content_type OWNER TO sgis;

--
-- Name: django_content_type_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE django_content_type_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.django_content_type_id_seq OWNER TO sgis;

--
-- Name: django_content_type_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE django_content_type_id_seq OWNED BY django_content_type.id;


--
-- Name: django_session; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE django_session (
    session_key character varying(40) NOT NULL,
    session_data text NOT NULL,
    expire_date timestamp with time zone NOT NULL
);


ALTER TABLE public.django_session OWNER TO sgis;

--
-- Name: django_site; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE django_site (
    id integer NOT NULL,
    domain character varying(100) NOT NULL,
    name character varying(50) NOT NULL
);


ALTER TABLE public.django_site OWNER TO sgis;

--
-- Name: django_site_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE django_site_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.django_site_id_seq OWNER TO sgis;

--
-- Name: django_site_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE django_site_id_seq OWNED BY django_site.id;


--
-- Name: djcelery_crontabschedule; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE djcelery_crontabschedule (
    id integer NOT NULL,
    minute character varying(64) NOT NULL,
    hour character varying(64) NOT NULL,
    day_of_week character varying(64) NOT NULL,
    day_of_month character varying(64) NOT NULL,
    month_of_year character varying(64) NOT NULL
);


ALTER TABLE public.djcelery_crontabschedule OWNER TO sgis;

--
-- Name: djcelery_crontabschedule_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE djcelery_crontabschedule_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.djcelery_crontabschedule_id_seq OWNER TO sgis;

--
-- Name: djcelery_crontabschedule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE djcelery_crontabschedule_id_seq OWNED BY djcelery_crontabschedule.id;


--
-- Name: djcelery_intervalschedule; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE djcelery_intervalschedule (
    id integer NOT NULL,
    every integer NOT NULL,
    period character varying(24) NOT NULL
);


ALTER TABLE public.djcelery_intervalschedule OWNER TO sgis;

--
-- Name: djcelery_intervalschedule_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE djcelery_intervalschedule_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.djcelery_intervalschedule_id_seq OWNER TO sgis;

--
-- Name: djcelery_intervalschedule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE djcelery_intervalschedule_id_seq OWNED BY djcelery_intervalschedule.id;


--
-- Name: djcelery_periodictask; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE djcelery_periodictask (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    task character varying(200) NOT NULL,
    interval_id integer,
    crontab_id integer,
    args text NOT NULL,
    kwargs text NOT NULL,
    queue character varying(200),
    exchange character varying(200),
    routing_key character varying(200),
    expires timestamp with time zone,
    enabled boolean NOT NULL,
    last_run_at timestamp with time zone,
    total_run_count integer NOT NULL,
    date_changed timestamp with time zone NOT NULL,
    description text NOT NULL,
    CONSTRAINT djcelery_periodictask_total_run_count_check CHECK ((total_run_count >= 0))
);


ALTER TABLE public.djcelery_periodictask OWNER TO sgis;

--
-- Name: djcelery_periodictask_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE djcelery_periodictask_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.djcelery_periodictask_id_seq OWNER TO sgis;

--
-- Name: djcelery_periodictask_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE djcelery_periodictask_id_seq OWNED BY djcelery_periodictask.id;


--
-- Name: djcelery_periodictasks; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE djcelery_periodictasks (
    ident smallint NOT NULL,
    last_update timestamp with time zone NOT NULL
);


ALTER TABLE public.djcelery_periodictasks OWNER TO sgis;

--
-- Name: djcelery_taskstate; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE djcelery_taskstate (
    id integer NOT NULL,
    state character varying(64) NOT NULL,
    task_id character varying(36) NOT NULL,
    name character varying(200),
    tstamp timestamp with time zone NOT NULL,
    args text,
    kwargs text,
    eta timestamp with time zone,
    expires timestamp with time zone,
    result text,
    traceback text,
    runtime double precision,
    retries integer NOT NULL,
    worker_id integer,
    hidden boolean NOT NULL
);


ALTER TABLE public.djcelery_taskstate OWNER TO sgis;

--
-- Name: djcelery_taskstate_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE djcelery_taskstate_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.djcelery_taskstate_id_seq OWNER TO sgis;

--
-- Name: djcelery_taskstate_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE djcelery_taskstate_id_seq OWNED BY djcelery_taskstate.id;


--
-- Name: djcelery_workerstate; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE djcelery_workerstate (
    id integer NOT NULL,
    hostname character varying(255) NOT NULL,
    last_heartbeat timestamp with time zone
);


ALTER TABLE public.djcelery_workerstate OWNER TO sgis;

--
-- Name: djcelery_workerstate_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE djcelery_workerstate_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.djcelery_workerstate_id_seq OWNER TO sgis;

--
-- Name: djcelery_workerstate_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE djcelery_workerstate_id_seq OWNED BY djcelery_workerstate.id;


--
-- Name: images_image; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE images_image (
    revisionplugin_ptr_id integer NOT NULL,
    image character varying(100) NOT NULL,
    caption character varying(2056)
);


ALTER TABLE public.images_image OWNER TO sgis;

--
-- Name: incident_attack_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE incident_attack_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.incident_attack_id_seq OWNER TO sgis;

--
-- Name: incident_attack; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incident_attack (
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    rt_id integer,
    subject character varying(200) NOT NULL,
    target_ip inet,
    incident_id integer NOT NULL,
    organization_id integer,
    creator_id integer NOT NULL,
    id integer DEFAULT nextval('incident_attack_id_seq'::regclass) NOT NULL
);


ALTER TABLE public.incident_attack OWNER TO sgis;

--
-- Name: incident_category; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incident_category (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    name character varying(50) NOT NULL,
    creator_id integer NOT NULL
);


ALTER TABLE public.incident_category OWNER TO sgis;

--
-- Name: incident_category_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE incident_category_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.incident_category_id_seq OWNER TO sgis;

--
-- Name: incident_category_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE incident_category_id_seq OWNED BY incident_category.id;


--
-- Name: incident_incident; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incident_incident (
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    rt_id integer NOT NULL,
    queue integer NOT NULL,
    subject character varying(200) NOT NULL,
    organization_id integer,
    creator_id integer NOT NULL,
    source_ip inet,
    complainer character varying(254),
    status integer NOT NULL,
    parent_id integer,
    resolved timestamp with time zone,
    type_id integer,
    notified timestamp with time zone NOT NULL,
    parser_result text NOT NULL,
    vulnerability boolean NOT NULL,
    aggregator_id integer
);


ALTER TABLE public.incident_incident OWNER TO sgis;

--
-- Name: incident_summary; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incident_summary (
    summary_date timestamp without time zone,
    last_update timestamp without time zone,
    organization_id integer NOT NULL,
    vulnerability boolean,
    closed integer DEFAULT 0,
    opened integer DEFAULT 0,
    missing integer DEFAULT 0,
    attacks_opened integer DEFAULT 0,
    closed_avg numeric(20,2) DEFAULT 0,
    missing_avg numeric(20,2) DEFAULT 0,
    score numeric(20,2) DEFAULT 0
);


ALTER TABLE public.incident_summary OWNER TO sgis;

--
-- Name: incident_summary_users; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incident_summary_users (
    summary_date timestamp without time zone,
    organization_id integer NOT NULL,
    user_id integer NOT NULL,
    permission integer
);


ALTER TABLE public.incident_summary_users OWNER TO sgis;

--
-- Name: organization_organization; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE organization_organization (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    parent_id integer,
    slug character varying(50) NOT NULL,
    title character varying(200) NOT NULL,
    state character varying(2) NOT NULL,
    creator_id integer NOT NULL,
    lft integer NOT NULL,
    rght integer NOT NULL,
    tree_id integer NOT NULL,
    level integer NOT NULL,
    acronym character varying(20) NOT NULL,
    CONSTRAINT organization_organization_level_check CHECK ((level >= 0)),
    CONSTRAINT organization_organization_lft_check CHECK ((lft >= 0)),
    CONSTRAINT organization_organization_rght_check CHECK ((rght >= 0)),
    CONSTRAINT organization_organization_tree_id_check CHECK ((tree_id >= 0))
);


ALTER TABLE public.organization_organization OWNER TO sgis;

--
-- Name: incident_summary_users_view; Type: VIEW; Schema: public; Owner: sgis
--

CREATE VIEW incident_summary_users_view AS
    SELECT incident_summary_users.summary_date, incident_summary_users.organization_id, CASE WHEN (incident_summary_users.permission = 0) THEN 'Analista'::text WHEN (incident_summary_users.permission = 1) THEN 'Administrador'::text ELSE '*error*'::text END AS permission, auth_user.email, (((auth_user.first_name)::text || ' '::text) || (auth_user.last_name)::text) AS name, account_profile.phone, account_profile.mobile, account_profile.voip, account_profile.pgp, account_profile.notes, organization_organization.title AS organization, organization_organization.acronym AS organization_acronym, organization_organization.level AS organization_level FROM (((incident_summary_users JOIN auth_user ON ((auth_user.id = incident_summary_users.user_id))) JOIN account_profile ON ((account_profile.user_id = incident_summary_users.user_id))) JOIN organization_organization ON ((organization_organization.id = incident_summary_users.organization_id)));


ALTER TABLE public.incident_summary_users_view OWNER TO sgis;

--
-- Name: incident_type; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incident_type (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    name character varying(50) NOT NULL,
    category_id integer NOT NULL,
    creator_id integer NOT NULL
);


ALTER TABLE public.incident_type OWNER TO sgis;

--
-- Name: incident_type_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE incident_type_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.incident_type_id_seq OWNER TO sgis;

--
-- Name: incident_type_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE incident_type_id_seq OWNED BY incident_type.id;


--
-- Name: incidentparser_historicalparser; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incidentparser_historicalparser (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    slug character varying(50) NOT NULL,
    title character varying(200) NOT NULL,
    code text NOT NULL,
    identifiers text NOT NULL,
    response_template text NOT NULL,
    creator_id integer,
    enabled boolean NOT NULL,
    type_id integer,
    history_id integer NOT NULL,
    history_date timestamp with time zone NOT NULL,
    history_user_id integer,
    history_type character varying(1) NOT NULL,
    acknowledge_template text,
    attack_template text
);


ALTER TABLE public.incidentparser_historicalparser OWNER TO sgis;

--
-- Name: incidentparser_historicalparser_history_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE incidentparser_historicalparser_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.incidentparser_historicalparser_history_id_seq OWNER TO sgis;

--
-- Name: incidentparser_historicalparser_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE incidentparser_historicalparser_history_id_seq OWNED BY incidentparser_historicalparser.history_id;


--
-- Name: incidentparser_incidentparser; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incidentparser_incidentparser (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    incident_id integer NOT NULL,
    parser_id integer,
    task_id character varying(255) NOT NULL
);


ALTER TABLE public.incidentparser_incidentparser OWNER TO sgis;

--
-- Name: incidentparser_incidentparser_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE incidentparser_incidentparser_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.incidentparser_incidentparser_id_seq OWNER TO sgis;

--
-- Name: incidentparser_incidentparser_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE incidentparser_incidentparser_id_seq OWNED BY incidentparser_incidentparser.id;


--
-- Name: incidentparser_parser; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE incidentparser_parser (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    slug character varying(50) NOT NULL,
    title character varying(200) NOT NULL,
    code text NOT NULL,
    creator_id integer NOT NULL,
    identifiers text NOT NULL,
    response_template text NOT NULL,
    enabled boolean NOT NULL,
    type_id integer,
    acknowledge_template text,
    attack_template text
);


ALTER TABLE public.incidentparser_parser OWNER TO sgis;

--
-- Name: incidentparser_parser_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE incidentparser_parser_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.incidentparser_parser_id_seq OWNER TO sgis;

--
-- Name: incidentparser_parser_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE incidentparser_parser_id_seq OWNED BY incidentparser_parser.id;


--
-- Name: network_network; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE network_network (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    ip_network cidr NOT NULL,
    creator_id integer NOT NULL,
    organization_id integer NOT NULL
);


ALTER TABLE public.network_network OWNER TO sgis;

--
-- Name: network_network_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE network_network_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.network_network_id_seq OWNER TO sgis;

--
-- Name: network_network_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE network_network_id_seq OWNED BY network_network.id;


--
-- Name: notify_notification; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE notify_notification (
    id integer NOT NULL,
    subscription_id integer,
    message text NOT NULL,
    url character varying(200),
    is_viewed boolean NOT NULL,
    is_emailed boolean NOT NULL,
    created timestamp with time zone NOT NULL,
    occurrences integer NOT NULL,
    CONSTRAINT ck_occurrences_pstv_7c1fdb8025227a17 CHECK ((occurrences >= 0)),
    CONSTRAINT notify_notification_occurrences_check CHECK ((occurrences >= 0))
);


ALTER TABLE public.notify_notification OWNER TO sgis;

--
-- Name: notify_notification_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE notify_notification_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.notify_notification_id_seq OWNER TO sgis;

--
-- Name: notify_notification_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE notify_notification_id_seq OWNED BY notify_notification.id;


--
-- Name: notify_notificationtype; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE notify_notificationtype (
    key character varying(128) NOT NULL,
    label character varying(128),
    content_type_id integer
);


ALTER TABLE public.notify_notificationtype OWNER TO sgis;

--
-- Name: notify_settings; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE notify_settings (
    id integer NOT NULL,
    user_id integer NOT NULL,
    "interval" smallint NOT NULL
);


ALTER TABLE public.notify_settings OWNER TO sgis;

--
-- Name: notify_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE notify_settings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.notify_settings_id_seq OWNER TO sgis;

--
-- Name: notify_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE notify_settings_id_seq OWNED BY notify_settings.id;


--
-- Name: notify_subscription; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE notify_subscription (
    id integer NOT NULL,
    settings_id integer NOT NULL,
    notification_type_id character varying(128) NOT NULL,
    object_id character varying(64),
    send_emails boolean NOT NULL,
    latest_id integer
);


ALTER TABLE public.notify_subscription OWNER TO sgis;

--
-- Name: notify_subscription_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE notify_subscription_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.notify_subscription_id_seq OWNER TO sgis;

--
-- Name: notify_subscription_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE notify_subscription_id_seq OWNED BY notify_subscription.id;


--
-- Name: organization_organization_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE organization_organization_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.organization_organization_id_seq OWNER TO sgis;

--
-- Name: organization_organization_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE organization_organization_id_seq OWNED BY organization_organization.id;


--
-- Name: organization_permission; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE organization_permission (
    id integer NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    permission integer NOT NULL,
    organization_id integer NOT NULL,
    user_id integer NOT NULL,
    creator_id integer NOT NULL,
    send_email boolean NOT NULL
);


ALTER TABLE public.organization_permission OWNER TO sgis;

--
-- Name: organization_permission_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE organization_permission_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.organization_permission_id_seq OWNER TO sgis;

--
-- Name: organization_permission_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE organization_permission_id_seq OWNED BY organization_permission.id;


--
-- Name: shibboleth_accessdenied; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE shibboleth_accessdenied (
    id integer NOT NULL,
    username character varying(75) NOT NULL,
    name character varying(100) NOT NULL,
    login_date timestamp with time zone NOT NULL
);


ALTER TABLE public.shibboleth_accessdenied OWNER TO sgis;

--
-- Name: shibboleth_accessdenied_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE shibboleth_accessdenied_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.shibboleth_accessdenied_id_seq OWNER TO sgis;

--
-- Name: shibboleth_accessdenied_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE shibboleth_accessdenied_id_seq OWNED BY shibboleth_accessdenied.id;


--
-- Name: south_migrationhistory; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE south_migrationhistory (
    id integer NOT NULL,
    app_name character varying(255) NOT NULL,
    migration character varying(255) NOT NULL,
    applied timestamp with time zone NOT NULL
);


ALTER TABLE public.south_migrationhistory OWNER TO sgis;

--
-- Name: south_migrationhistory_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE south_migrationhistory_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.south_migrationhistory_id_seq OWNER TO sgis;

--
-- Name: south_migrationhistory_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE south_migrationhistory_id_seq OWNED BY south_migrationhistory.id;


--
-- Name: thumbnail_kvstore; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE thumbnail_kvstore (
    key character varying(200) NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.thumbnail_kvstore OWNER TO sgis;

--
-- Name: tree_incident; Type: VIEW; Schema: public; Owner: sgis
--

CREATE VIEW tree_incident AS
    SELECT incident_incident.rt_id AS id, incident_incident.notified AS created, incident_incident.modified, incident_incident.resolved, incident_incident.subject, incident_incident.vulnerability, CASE WHEN (incident_incident.status = ANY (ARRAY[0, 2, 3])) THEN 'Pendente'::text WHEN (incident_incident.status = 1) THEN 'Resolvido'::text ELSE '*error*'::text END AS status, CASE WHEN (incident_incident.queue = 0) THEN 'Pendentes'::text WHEN (incident_incident.queue = 1) THEN 'Manual'::text WHEN (incident_incident.queue = 2) THEN 'Processados'::text WHEN (incident_incident.queue = 3) THEN 'Falhas'::text WHEN (incident_incident.queue = 4) THEN 'Outros'::text ELSE '*error*'::text END AS queue, organization_organization.id AS organization_id, COALESCE(NULLIF((organization_organization.acronym)::text, ''::text), (organization_organization.title)::text) AS organization_title, incident_type.name AS incident_type, incident_category.name AS category FROM (((incident_incident JOIN organization_organization ON ((organization_organization.id = incident_incident.organization_id))) LEFT JOIN incident_type ON ((incident_type.id = incident_incident.type_id))) LEFT JOIN incident_category ON ((incident_category.id = incident_type.category_id)));


ALTER TABLE public.tree_incident OWNER TO sgis;

--
-- Name: tree_attack; Type: VIEW; Schema: public; Owner: sgis
--

CREATE VIEW tree_attack AS
    SELECT incident_attack.rt_id AS id, incident_attack.created, incident_attack.modified, incident_attack.subject, COALESCE(tree_incident.status, 'Desconhecido'::text) AS status, COALESCE(tree_incident.queue, 'Desconhecido'::text) AS queue, COALESCE(tree_incident.category, 'Desconhecido'::character varying) AS category, organization_organization.id AS organization_id, COALESCE(NULLIF((organization_organization.acronym)::text, ''::text), (organization_organization.title)::text) AS organization_title FROM ((incident_attack JOIN organization_organization ON ((organization_organization.id = incident_attack.organization_id))) LEFT JOIN tree_incident ON ((tree_incident.id = incident_attack.incident_id)));


ALTER TABLE public.tree_attack OWNER TO sgis;

--
-- Name: whitelist_whitelist; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE whitelist_whitelist (
    id integer NOT NULL,
    ip_network character varying(42) NOT NULL
);


ALTER TABLE public.whitelist_whitelist OWNER TO sgis;

--
-- Name: whitelist_whitelist_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE whitelist_whitelist_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.whitelist_whitelist_id_seq OWNER TO sgis;

--
-- Name: whitelist_whitelist_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE whitelist_whitelist_id_seq OWNED BY whitelist_whitelist.id;


--
-- Name: whitelist_whitelisttime; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE whitelist_whitelisttime (
    id integer NOT NULL,
    date timestamp with time zone NOT NULL,
    whitelist_id integer NOT NULL
);


ALTER TABLE public.whitelist_whitelisttime OWNER TO sgis;

--
-- Name: whitelist_whitelisttime_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE whitelist_whitelisttime_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.whitelist_whitelisttime_id_seq OWNER TO sgis;

--
-- Name: whitelist_whitelisttime_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE whitelist_whitelisttime_id_seq OWNED BY whitelist_whitelisttime.id;


--
-- Name: wiki_article; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_article (
    id integer NOT NULL,
    current_revision_id integer,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    owner_id integer,
    group_id integer,
    group_read boolean NOT NULL,
    group_write boolean NOT NULL,
    other_read boolean NOT NULL,
    other_write boolean NOT NULL
);


ALTER TABLE public.wiki_article OWNER TO sgis;

--
-- Name: wiki_article_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE wiki_article_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_article_id_seq OWNER TO sgis;

--
-- Name: wiki_article_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE wiki_article_id_seq OWNED BY wiki_article.id;


--
-- Name: wiki_articleforobject; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_articleforobject (
    id integer NOT NULL,
    article_id integer NOT NULL,
    content_type_id integer NOT NULL,
    object_id integer NOT NULL,
    is_mptt boolean NOT NULL,
    CONSTRAINT wiki_articleforobject_object_id_check CHECK ((object_id >= 0))
);


ALTER TABLE public.wiki_articleforobject OWNER TO sgis;

--
-- Name: wiki_articleforobject_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE wiki_articleforobject_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_articleforobject_id_seq OWNER TO sgis;

--
-- Name: wiki_articleforobject_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE wiki_articleforobject_id_seq OWNED BY wiki_articleforobject.id;


--
-- Name: wiki_articleplugin; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_articleplugin (
    id integer NOT NULL,
    article_id integer NOT NULL,
    deleted boolean NOT NULL,
    created timestamp with time zone NOT NULL
);


ALTER TABLE public.wiki_articleplugin OWNER TO sgis;

--
-- Name: wiki_articleplugin_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE wiki_articleplugin_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_articleplugin_id_seq OWNER TO sgis;

--
-- Name: wiki_articleplugin_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE wiki_articleplugin_id_seq OWNED BY wiki_articleplugin.id;


--
-- Name: wiki_articlerevision; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_articlerevision (
    id integer NOT NULL,
    revision_number integer NOT NULL,
    user_message text NOT NULL,
    automatic_log text NOT NULL,
    ip_address inet,
    user_id integer,
    modified timestamp with time zone NOT NULL,
    created timestamp with time zone NOT NULL,
    previous_revision_id integer,
    deleted boolean NOT NULL,
    locked boolean NOT NULL,
    article_id integer NOT NULL,
    content text NOT NULL,
    title character varying(512) NOT NULL
);


ALTER TABLE public.wiki_articlerevision OWNER TO sgis;

--
-- Name: wiki_articlerevision_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE wiki_articlerevision_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_articlerevision_id_seq OWNER TO sgis;

--
-- Name: wiki_articlerevision_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE wiki_articlerevision_id_seq OWNED BY wiki_articlerevision.id;


--
-- Name: wiki_articlesubscription; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_articlesubscription (
    subscription_ptr_id integer NOT NULL,
    articleplugin_ptr_id integer NOT NULL
);


ALTER TABLE public.wiki_articlesubscription OWNER TO sgis;

--
-- Name: wiki_attachment; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_attachment (
    reusableplugin_ptr_id integer NOT NULL,
    current_revision_id integer,
    original_filename character varying(256)
);


ALTER TABLE public.wiki_attachment OWNER TO sgis;

--
-- Name: wiki_attachmentrevision; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_attachmentrevision (
    id integer NOT NULL,
    revision_number integer NOT NULL,
    user_message text NOT NULL,
    automatic_log text NOT NULL,
    ip_address inet,
    user_id integer,
    modified timestamp with time zone NOT NULL,
    created timestamp with time zone NOT NULL,
    previous_revision_id integer,
    deleted boolean NOT NULL,
    locked boolean NOT NULL,
    attachment_id integer NOT NULL,
    file character varying(255) NOT NULL,
    description text NOT NULL
);


ALTER TABLE public.wiki_attachmentrevision OWNER TO sgis;

--
-- Name: wiki_attachmentrevision_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE wiki_attachmentrevision_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_attachmentrevision_id_seq OWNER TO sgis;

--
-- Name: wiki_attachmentrevision_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE wiki_attachmentrevision_id_seq OWNED BY wiki_attachmentrevision.id;


--
-- Name: wiki_image; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_image (
    revisionplugin_ptr_id integer NOT NULL
);


ALTER TABLE public.wiki_image OWNER TO sgis;

--
-- Name: wiki_imagerevision; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_imagerevision (
    revisionpluginrevision_ptr_id integer NOT NULL,
    image character varying(2000),
    width smallint,
    height smallint
);


ALTER TABLE public.wiki_imagerevision OWNER TO sgis;

--
-- Name: wiki_reusableplugin; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_reusableplugin (
    articleplugin_ptr_id integer NOT NULL
);


ALTER TABLE public.wiki_reusableplugin OWNER TO sgis;

--
-- Name: wiki_reusableplugin_articles; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_reusableplugin_articles (
    id integer NOT NULL,
    reusableplugin_id integer NOT NULL,
    article_id integer NOT NULL
);


ALTER TABLE public.wiki_reusableplugin_articles OWNER TO sgis;

--
-- Name: wiki_reusableplugin_articles_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE wiki_reusableplugin_articles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_reusableplugin_articles_id_seq OWNER TO sgis;

--
-- Name: wiki_reusableplugin_articles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE wiki_reusableplugin_articles_id_seq OWNED BY wiki_reusableplugin_articles.id;


--
-- Name: wiki_revisionplugin; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_revisionplugin (
    articleplugin_ptr_id integer NOT NULL,
    current_revision_id integer
);


ALTER TABLE public.wiki_revisionplugin OWNER TO sgis;

--
-- Name: wiki_revisionpluginrevision; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_revisionpluginrevision (
    id integer NOT NULL,
    revision_number integer NOT NULL,
    user_message text NOT NULL,
    automatic_log text NOT NULL,
    ip_address inet,
    user_id integer,
    modified timestamp with time zone NOT NULL,
    created timestamp with time zone NOT NULL,
    previous_revision_id integer,
    deleted boolean NOT NULL,
    locked boolean NOT NULL,
    plugin_id integer NOT NULL
);


ALTER TABLE public.wiki_revisionpluginrevision OWNER TO sgis;

--
-- Name: wiki_revisionpluginrevision_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE wiki_revisionpluginrevision_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_revisionpluginrevision_id_seq OWNER TO sgis;

--
-- Name: wiki_revisionpluginrevision_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE wiki_revisionpluginrevision_id_seq OWNED BY wiki_revisionpluginrevision.id;


--
-- Name: wiki_simpleplugin; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_simpleplugin (
    articleplugin_ptr_id integer NOT NULL,
    article_revision_id integer NOT NULL
);


ALTER TABLE public.wiki_simpleplugin OWNER TO sgis;

--
-- Name: wiki_urlpath; Type: TABLE; Schema: public; Owner: sgis; Tablespace: 
--

CREATE TABLE wiki_urlpath (
    id integer NOT NULL,
    slug character varying(50),
    site_id integer NOT NULL,
    parent_id integer,
    lft integer NOT NULL,
    rght integer NOT NULL,
    tree_id integer NOT NULL,
    level integer NOT NULL,
    article_id integer DEFAULT 1 NOT NULL,
    CONSTRAINT wiki_urlpath_level_check CHECK ((level >= 0)),
    CONSTRAINT wiki_urlpath_lft_check CHECK ((lft >= 0)),
    CONSTRAINT wiki_urlpath_rght_check CHECK ((rght >= 0)),
    CONSTRAINT wiki_urlpath_tree_id_check CHECK ((tree_id >= 0))
);


ALTER TABLE public.wiki_urlpath OWNER TO sgis;

--
-- Name: wiki_urlpath_id_seq; Type: SEQUENCE; Schema: public; Owner: sgis
--

CREATE SEQUENCE wiki_urlpath_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_urlpath_id_seq OWNER TO sgis;

--
-- Name: wiki_urlpath_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sgis
--

ALTER SEQUENCE wiki_urlpath_id_seq OWNED BY wiki_urlpath.id;


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY actstream_action ALTER COLUMN id SET DEFAULT nextval('actstream_action_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY actstream_follow ALTER COLUMN id SET DEFAULT nextval('actstream_follow_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY aggregation_rememberconfig ALTER COLUMN id SET DEFAULT nextval('aggregation_rememberconfig_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY attachments_attachmentrevision ALTER COLUMN id SET DEFAULT nextval('attachments_attachmentrevision_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_group ALTER COLUMN id SET DEFAULT nextval('auth_group_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_group_permissions ALTER COLUMN id SET DEFAULT nextval('auth_group_permissions_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_permission ALTER COLUMN id SET DEFAULT nextval('auth_permission_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_user ALTER COLUMN id SET DEFAULT nextval('auth_user_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_user_groups ALTER COLUMN id SET DEFAULT nextval('auth_user_groups_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_user_user_permissions ALTER COLUMN id SET DEFAULT nextval('auth_user_user_permissions_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY celery_taskmeta ALTER COLUMN id SET DEFAULT nextval('celery_taskmeta_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY celery_tasksetmeta ALTER COLUMN id SET DEFAULT nextval('celery_tasksetmeta_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY contact_contact ALTER COLUMN id SET DEFAULT nextval('contact_contact_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY contact_contact_organizations ALTER COLUMN id SET DEFAULT nextval('contact_contact_organizations_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY django_admin_log ALTER COLUMN id SET DEFAULT nextval('django_admin_log_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY django_content_type ALTER COLUMN id SET DEFAULT nextval('django_content_type_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY django_site ALTER COLUMN id SET DEFAULT nextval('django_site_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY djcelery_crontabschedule ALTER COLUMN id SET DEFAULT nextval('djcelery_crontabschedule_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY djcelery_intervalschedule ALTER COLUMN id SET DEFAULT nextval('djcelery_intervalschedule_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY djcelery_periodictask ALTER COLUMN id SET DEFAULT nextval('djcelery_periodictask_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY djcelery_taskstate ALTER COLUMN id SET DEFAULT nextval('djcelery_taskstate_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY djcelery_workerstate ALTER COLUMN id SET DEFAULT nextval('djcelery_workerstate_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_category ALTER COLUMN id SET DEFAULT nextval('incident_category_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_type ALTER COLUMN id SET DEFAULT nextval('incident_type_id_seq'::regclass);


--
-- Name: history_id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incidentparser_historicalparser ALTER COLUMN history_id SET DEFAULT nextval('incidentparser_historicalparser_history_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incidentparser_incidentparser ALTER COLUMN id SET DEFAULT nextval('incidentparser_incidentparser_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incidentparser_parser ALTER COLUMN id SET DEFAULT nextval('incidentparser_parser_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY network_network ALTER COLUMN id SET DEFAULT nextval('network_network_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_notification ALTER COLUMN id SET DEFAULT nextval('notify_notification_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_settings ALTER COLUMN id SET DEFAULT nextval('notify_settings_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_subscription ALTER COLUMN id SET DEFAULT nextval('notify_subscription_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY organization_organization ALTER COLUMN id SET DEFAULT nextval('organization_organization_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY organization_permission ALTER COLUMN id SET DEFAULT nextval('organization_permission_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY shibboleth_accessdenied ALTER COLUMN id SET DEFAULT nextval('shibboleth_accessdenied_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY south_migrationhistory ALTER COLUMN id SET DEFAULT nextval('south_migrationhistory_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY whitelist_whitelist ALTER COLUMN id SET DEFAULT nextval('whitelist_whitelist_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY whitelist_whitelisttime ALTER COLUMN id SET DEFAULT nextval('whitelist_whitelisttime_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_article ALTER COLUMN id SET DEFAULT nextval('wiki_article_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articleforobject ALTER COLUMN id SET DEFAULT nextval('wiki_articleforobject_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articleplugin ALTER COLUMN id SET DEFAULT nextval('wiki_articleplugin_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articlerevision ALTER COLUMN id SET DEFAULT nextval('wiki_articlerevision_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_attachmentrevision ALTER COLUMN id SET DEFAULT nextval('wiki_attachmentrevision_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_reusableplugin_articles ALTER COLUMN id SET DEFAULT nextval('wiki_reusableplugin_articles_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_revisionpluginrevision ALTER COLUMN id SET DEFAULT nextval('wiki_revisionpluginrevision_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_urlpath ALTER COLUMN id SET DEFAULT nextval('wiki_urlpath_id_seq'::regclass);


--
-- Name: account_profile_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY account_profile
    ADD CONSTRAINT account_profile_pkey PRIMARY KEY (user_id);


--
-- Name: actstream_action_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY actstream_action
    ADD CONSTRAINT actstream_action_pkey PRIMARY KEY (id);


--
-- Name: actstream_follow_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY actstream_follow
    ADD CONSTRAINT actstream_follow_pkey PRIMARY KEY (id);


--
-- Name: actstream_follow_user_id_49f02cb6d67a13f2_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY actstream_follow
    ADD CONSTRAINT actstream_follow_user_id_49f02cb6d67a13f2_uniq UNIQUE (user_id, content_type_id, object_id);


--
-- Name: aggregation_rememberconfig_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY aggregation_rememberconfig
    ADD CONSTRAINT aggregation_rememberconfig_pkey PRIMARY KEY (id);


--
-- Name: attachments_attachment_current_revision_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY attachments_attachment
    ADD CONSTRAINT attachments_attachment_current_revision_id_key UNIQUE (current_revision_id);


--
-- Name: attachments_attachment_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY attachments_attachment
    ADD CONSTRAINT attachments_attachment_pkey PRIMARY KEY (reusableplugin_ptr_id);


--
-- Name: attachments_attachmentrevision_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY attachments_attachmentrevision
    ADD CONSTRAINT attachments_attachmentrevision_pkey PRIMARY KEY (id);


--
-- Name: auth_group_name_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_group
    ADD CONSTRAINT auth_group_name_key UNIQUE (name);


--
-- Name: auth_group_permissions_group_id_permission_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_permission_id_key UNIQUE (group_id, permission_id);


--
-- Name: auth_group_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_pkey PRIMARY KEY (id);


--
-- Name: auth_group_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_group
    ADD CONSTRAINT auth_group_pkey PRIMARY KEY (id);


--
-- Name: auth_permission_content_type_id_codename_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_codename_key UNIQUE (content_type_id, codename);


--
-- Name: auth_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_permission
    ADD CONSTRAINT auth_permission_pkey PRIMARY KEY (id);


--
-- Name: auth_user_email_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_user
    ADD CONSTRAINT auth_user_email_key UNIQUE (email);


--
-- Name: auth_user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_user_groups
    ADD CONSTRAINT auth_user_groups_pkey PRIMARY KEY (id);


--
-- Name: auth_user_groups_user_id_group_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_user_groups
    ADD CONSTRAINT auth_user_groups_user_id_group_id_key UNIQUE (user_id, group_id);


--
-- Name: auth_user_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_user
    ADD CONSTRAINT auth_user_pkey PRIMARY KEY (id);


--
-- Name: auth_user_user_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_pkey PRIMARY KEY (id);


--
-- Name: auth_user_user_permissions_user_id_permission_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_user_id_permission_id_key UNIQUE (user_id, permission_id);


--
-- Name: auth_user_username_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY auth_user
    ADD CONSTRAINT auth_user_username_key UNIQUE (username);


--
-- Name: celery_taskmeta_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY celery_taskmeta
    ADD CONSTRAINT celery_taskmeta_pkey PRIMARY KEY (id);


--
-- Name: celery_taskmeta_task_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY celery_taskmeta
    ADD CONSTRAINT celery_taskmeta_task_id_key UNIQUE (task_id);


--
-- Name: celery_tasksetmeta_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY celery_tasksetmeta
    ADD CONSTRAINT celery_tasksetmeta_pkey PRIMARY KEY (id);


--
-- Name: celery_tasksetmeta_taskset_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY celery_tasksetmeta
    ADD CONSTRAINT celery_tasksetmeta_taskset_id_key UNIQUE (taskset_id);


--
-- Name: contact_contact_email_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY contact_contact
    ADD CONSTRAINT contact_contact_email_key UNIQUE (email);


--
-- Name: contact_contact_name_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY contact_contact
    ADD CONSTRAINT contact_contact_name_key UNIQUE (name);


--
-- Name: contact_contact_organizations_contact_id_3a2230bd1c0992ef_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY contact_contact_organizations
    ADD CONSTRAINT contact_contact_organizations_contact_id_3a2230bd1c0992ef_uniq UNIQUE (contact_id, organization_id);


--
-- Name: contact_contact_organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY contact_contact_organizations
    ADD CONSTRAINT contact_contact_organizations_pkey PRIMARY KEY (id);


--
-- Name: contact_contact_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY contact_contact
    ADD CONSTRAINT contact_contact_pkey PRIMARY KEY (id);


--
-- Name: contact_contact_slug_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY contact_contact
    ADD CONSTRAINT contact_contact_slug_key UNIQUE (slug);


--
-- Name: django_admin_log_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY django_admin_log
    ADD CONSTRAINT django_admin_log_pkey PRIMARY KEY (id);


--
-- Name: django_content_type_app_label_model_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY django_content_type
    ADD CONSTRAINT django_content_type_app_label_model_key UNIQUE (app_label, model);


--
-- Name: django_content_type_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY django_content_type
    ADD CONSTRAINT django_content_type_pkey PRIMARY KEY (id);


--
-- Name: django_session_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY django_session
    ADD CONSTRAINT django_session_pkey PRIMARY KEY (session_key);


--
-- Name: django_site_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY django_site
    ADD CONSTRAINT django_site_pkey PRIMARY KEY (id);


--
-- Name: djcelery_crontabschedule_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_crontabschedule
    ADD CONSTRAINT djcelery_crontabschedule_pkey PRIMARY KEY (id);


--
-- Name: djcelery_intervalschedule_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_intervalschedule
    ADD CONSTRAINT djcelery_intervalschedule_pkey PRIMARY KEY (id);


--
-- Name: djcelery_periodictask_name_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_periodictask
    ADD CONSTRAINT djcelery_periodictask_name_key UNIQUE (name);


--
-- Name: djcelery_periodictask_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_periodictask
    ADD CONSTRAINT djcelery_periodictask_pkey PRIMARY KEY (id);


--
-- Name: djcelery_periodictasks_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_periodictasks
    ADD CONSTRAINT djcelery_periodictasks_pkey PRIMARY KEY (ident);


--
-- Name: djcelery_taskstate_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_taskstate
    ADD CONSTRAINT djcelery_taskstate_pkey PRIMARY KEY (id);


--
-- Name: djcelery_taskstate_task_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_taskstate
    ADD CONSTRAINT djcelery_taskstate_task_id_key UNIQUE (task_id);


--
-- Name: djcelery_workerstate_hostname_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_workerstate
    ADD CONSTRAINT djcelery_workerstate_hostname_key UNIQUE (hostname);


--
-- Name: djcelery_workerstate_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY djcelery_workerstate
    ADD CONSTRAINT djcelery_workerstate_pkey PRIMARY KEY (id);


--
-- Name: images_image_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY images_image
    ADD CONSTRAINT images_image_pkey PRIMARY KEY (revisionplugin_ptr_id);


--
-- Name: incident_attack_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incident_attack
    ADD CONSTRAINT incident_attack_pkey PRIMARY KEY (id);


--
-- Name: incident_attack_target_ip_66c7c10eccec5c3b_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incident_attack
    ADD CONSTRAINT incident_attack_target_ip_66c7c10eccec5c3b_uniq UNIQUE (target_ip, incident_id);


--
-- Name: incident_category_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incident_category
    ADD CONSTRAINT incident_category_pkey PRIMARY KEY (id);


--
-- Name: incident_incident_rt_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incident_incident
    ADD CONSTRAINT incident_incident_rt_id_key UNIQUE (rt_id);


--
-- Name: incident_summary_summary_date_organization_id_vulnerability_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incident_summary
    ADD CONSTRAINT incident_summary_summary_date_organization_id_vulnerability_key UNIQUE (summary_date, organization_id, vulnerability);


--
-- Name: incident_summary_users_summary_date_organization_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incident_summary_users
    ADD CONSTRAINT incident_summary_users_summary_date_organization_id_user_id_key UNIQUE (summary_date, organization_id, user_id);


--
-- Name: incident_type_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incident_type
    ADD CONSTRAINT incident_type_pkey PRIMARY KEY (id);


--
-- Name: incidentparser_historicalparser_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incidentparser_historicalparser
    ADD CONSTRAINT incidentparser_historicalparser_pkey PRIMARY KEY (history_id);


--
-- Name: incidentparser_incidentparser_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incidentparser_incidentparser
    ADD CONSTRAINT incidentparser_incidentparser_pkey PRIMARY KEY (id);


--
-- Name: incidentparser_incidentparser_task_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incidentparser_incidentparser
    ADD CONSTRAINT incidentparser_incidentparser_task_id_key UNIQUE (task_id);


--
-- Name: incidentparser_parser_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incidentparser_parser
    ADD CONSTRAINT incidentparser_parser_pkey PRIMARY KEY (id);


--
-- Name: incidentparser_parser_slug_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incidentparser_parser
    ADD CONSTRAINT incidentparser_parser_slug_key UNIQUE (slug);


--
-- Name: incidentparser_parser_title_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY incidentparser_parser
    ADD CONSTRAINT incidentparser_parser_title_key UNIQUE (title);


--
-- Name: network_network_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY network_network
    ADD CONSTRAINT network_network_pkey PRIMARY KEY (id);


--
-- Name: notify_notification_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY notify_notification
    ADD CONSTRAINT notify_notification_pkey PRIMARY KEY (id);


--
-- Name: notify_notificationtype_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY notify_notificationtype
    ADD CONSTRAINT notify_notificationtype_pkey PRIMARY KEY (key);


--
-- Name: notify_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY notify_settings
    ADD CONSTRAINT notify_settings_pkey PRIMARY KEY (id);


--
-- Name: notify_subscription_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY notify_subscription
    ADD CONSTRAINT notify_subscription_pkey PRIMARY KEY (id);


--
-- Name: organization_organization_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY organization_organization
    ADD CONSTRAINT organization_organization_pkey PRIMARY KEY (id);


--
-- Name: organization_organization_slug_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY organization_organization
    ADD CONSTRAINT organization_organization_slug_key UNIQUE (slug);


--
-- Name: organization_organization_title_20322d25c1f484be_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY organization_organization
    ADD CONSTRAINT organization_organization_title_20322d25c1f484be_uniq UNIQUE (title, tree_id);


--
-- Name: organization_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY organization_permission
    ADD CONSTRAINT organization_permission_pkey PRIMARY KEY (id);


--
-- Name: organization_permission_user_id_7055e7a5e46fc30_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY organization_permission
    ADD CONSTRAINT organization_permission_user_id_7055e7a5e46fc30_uniq UNIQUE (user_id, organization_id);


--
-- Name: shibboleth_accessdenied_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY shibboleth_accessdenied
    ADD CONSTRAINT shibboleth_accessdenied_pkey PRIMARY KEY (id);


--
-- Name: south_migrationhistory_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY south_migrationhistory
    ADD CONSTRAINT south_migrationhistory_pkey PRIMARY KEY (id);


--
-- Name: thumbnail_kvstore_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY thumbnail_kvstore
    ADD CONSTRAINT thumbnail_kvstore_pkey PRIMARY KEY (key);


--
-- Name: whitelist_whitelist_ip_network_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY whitelist_whitelist
    ADD CONSTRAINT whitelist_whitelist_ip_network_key UNIQUE (ip_network);


--
-- Name: whitelist_whitelist_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY whitelist_whitelist
    ADD CONSTRAINT whitelist_whitelist_pkey PRIMARY KEY (id);


--
-- Name: whitelist_whitelisttime_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY whitelist_whitelisttime
    ADD CONSTRAINT whitelist_whitelisttime_pkey PRIMARY KEY (id);


--
-- Name: wiki_article_current_revision_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_article
    ADD CONSTRAINT wiki_article_current_revision_id_key UNIQUE (current_revision_id);


--
-- Name: wiki_article_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_article
    ADD CONSTRAINT wiki_article_pkey PRIMARY KEY (id);


--
-- Name: wiki_articleforobject_content_type_id_27c4cce189b3bcab_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_articleforobject
    ADD CONSTRAINT wiki_articleforobject_content_type_id_27c4cce189b3bcab_uniq UNIQUE (content_type_id, object_id);


--
-- Name: wiki_articleforobject_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_articleforobject
    ADD CONSTRAINT wiki_articleforobject_pkey PRIMARY KEY (id);


--
-- Name: wiki_articleplugin_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_articleplugin
    ADD CONSTRAINT wiki_articleplugin_pkey PRIMARY KEY (id);


--
-- Name: wiki_articlerevision_article_id_4b4e7910c8e7b2d0_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_articlerevision
    ADD CONSTRAINT wiki_articlerevision_article_id_4b4e7910c8e7b2d0_uniq UNIQUE (article_id, revision_number);


--
-- Name: wiki_articlerevision_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_articlerevision
    ADD CONSTRAINT wiki_articlerevision_pkey PRIMARY KEY (id);


--
-- Name: wiki_articlesubscription_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_articlesubscription
    ADD CONSTRAINT wiki_articlesubscription_pkey PRIMARY KEY (articleplugin_ptr_id);


--
-- Name: wiki_articlesubscription_subscription_ptr_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_articlesubscription
    ADD CONSTRAINT wiki_articlesubscription_subscription_ptr_id_key UNIQUE (subscription_ptr_id);


--
-- Name: wiki_attachment_current_revision_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_attachment
    ADD CONSTRAINT wiki_attachment_current_revision_id_key UNIQUE (current_revision_id);


--
-- Name: wiki_attachment_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_attachment
    ADD CONSTRAINT wiki_attachment_pkey PRIMARY KEY (reusableplugin_ptr_id);


--
-- Name: wiki_attachmentrevision_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_attachmentrevision
    ADD CONSTRAINT wiki_attachmentrevision_pkey PRIMARY KEY (id);


--
-- Name: wiki_image_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_image
    ADD CONSTRAINT wiki_image_pkey PRIMARY KEY (revisionplugin_ptr_id);


--
-- Name: wiki_imagerevision_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_imagerevision
    ADD CONSTRAINT wiki_imagerevision_pkey PRIMARY KEY (revisionpluginrevision_ptr_id);


--
-- Name: wiki_reusableplugin_art_reusableplugin_id_6e34ac94afa8f9f2_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_reusableplugin_articles
    ADD CONSTRAINT wiki_reusableplugin_art_reusableplugin_id_6e34ac94afa8f9f2_uniq UNIQUE (reusableplugin_id, article_id);


--
-- Name: wiki_reusableplugin_articles_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_reusableplugin_articles
    ADD CONSTRAINT wiki_reusableplugin_articles_pkey PRIMARY KEY (id);


--
-- Name: wiki_reusableplugin_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_reusableplugin
    ADD CONSTRAINT wiki_reusableplugin_pkey PRIMARY KEY (articleplugin_ptr_id);


--
-- Name: wiki_revisionplugin_current_revision_id_key; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_revisionplugin
    ADD CONSTRAINT wiki_revisionplugin_current_revision_id_key UNIQUE (current_revision_id);


--
-- Name: wiki_revisionplugin_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_revisionplugin
    ADD CONSTRAINT wiki_revisionplugin_pkey PRIMARY KEY (articleplugin_ptr_id);


--
-- Name: wiki_revisionpluginrevision_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_revisionpluginrevision
    ADD CONSTRAINT wiki_revisionpluginrevision_pkey PRIMARY KEY (id);


--
-- Name: wiki_simpleplugin_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_simpleplugin
    ADD CONSTRAINT wiki_simpleplugin_pkey PRIMARY KEY (articleplugin_ptr_id);


--
-- Name: wiki_urlpath_pkey; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_urlpath
    ADD CONSTRAINT wiki_urlpath_pkey PRIMARY KEY (id);


--
-- Name: wiki_urlpath_site_id_124f6aa7b2cc9b82_uniq; Type: CONSTRAINT; Schema: public; Owner: sgis; Tablespace: 
--

ALTER TABLE ONLY wiki_urlpath
    ADD CONSTRAINT wiki_urlpath_site_id_124f6aa7b2cc9b82_uniq UNIQUE (site_id, parent_id, slug);


--
-- Name: account_profile_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX account_profile_creator_id ON account_profile USING btree (creator_id);


--
-- Name: account_profile_expires; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX account_profile_expires ON account_profile USING btree (expires);


--
-- Name: account_profile_function; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX account_profile_function ON account_profile USING btree (function);


--
-- Name: account_profile_home_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX account_profile_home_id ON account_profile USING btree (home_id);


--
-- Name: actstream_action_action_object_content_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX actstream_action_action_object_content_type_id ON actstream_action USING btree (action_object_content_type_id);


--
-- Name: actstream_action_actor_content_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX actstream_action_actor_content_type_id ON actstream_action USING btree (actor_content_type_id);


--
-- Name: actstream_action_target_content_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX actstream_action_target_content_type_id ON actstream_action USING btree (target_content_type_id);


--
-- Name: actstream_follow_content_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX actstream_follow_content_type_id ON actstream_follow USING btree (content_type_id);


--
-- Name: actstream_follow_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX actstream_follow_user_id ON actstream_follow USING btree (user_id);


--
-- Name: attachments_attachmentrevision_attachment_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX attachments_attachmentrevision_attachment_id ON attachments_attachmentrevision USING btree (attachment_id);


--
-- Name: attachments_attachmentrevision_previous_revision_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX attachments_attachmentrevision_previous_revision_id ON attachments_attachmentrevision USING btree (previous_revision_id);


--
-- Name: attachments_attachmentrevision_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX attachments_attachmentrevision_user_id ON attachments_attachmentrevision USING btree (user_id);


--
-- Name: auth_group_name_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_group_name_like ON auth_group USING btree (name varchar_pattern_ops);


--
-- Name: auth_group_permissions_group_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_group_permissions_group_id ON auth_group_permissions USING btree (group_id);


--
-- Name: auth_group_permissions_permission_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_group_permissions_permission_id ON auth_group_permissions USING btree (permission_id);


--
-- Name: auth_permission_content_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_permission_content_type_id ON auth_permission USING btree (content_type_id);


--
-- Name: auth_user_email_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_user_email_like ON auth_user USING btree (email varchar_pattern_ops);


--
-- Name: auth_user_groups_group_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_user_groups_group_id ON auth_user_groups USING btree (group_id);


--
-- Name: auth_user_groups_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_user_groups_user_id ON auth_user_groups USING btree (user_id);


--
-- Name: auth_user_user_permissions_permission_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_user_user_permissions_permission_id ON auth_user_user_permissions USING btree (permission_id);


--
-- Name: auth_user_user_permissions_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_user_user_permissions_user_id ON auth_user_user_permissions USING btree (user_id);


--
-- Name: auth_user_username_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX auth_user_username_like ON auth_user USING btree (username varchar_pattern_ops);


--
-- Name: celery_taskmeta_hidden; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX celery_taskmeta_hidden ON celery_taskmeta USING btree (hidden);


--
-- Name: celery_taskmeta_task_id_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX celery_taskmeta_task_id_like ON celery_taskmeta USING btree (task_id varchar_pattern_ops);


--
-- Name: celery_tasksetmeta_hidden; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX celery_tasksetmeta_hidden ON celery_tasksetmeta USING btree (hidden);


--
-- Name: celery_tasksetmeta_taskset_id_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX celery_tasksetmeta_taskset_id_like ON celery_tasksetmeta USING btree (taskset_id varchar_pattern_ops);


--
-- Name: contact_contact_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX contact_contact_creator_id ON contact_contact USING btree (creator_id);


--
-- Name: contact_contact_email_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX contact_contact_email_like ON contact_contact USING btree (email varchar_pattern_ops);


--
-- Name: contact_contact_name_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX contact_contact_name_like ON contact_contact USING btree (name varchar_pattern_ops);


--
-- Name: contact_contact_organizations_contact_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX contact_contact_organizations_contact_id ON contact_contact_organizations USING btree (contact_id);


--
-- Name: contact_contact_organizations_organization_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX contact_contact_organizations_organization_id ON contact_contact_organizations USING btree (organization_id);


--
-- Name: contact_contact_phone_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX contact_contact_phone_like ON contact_contact USING btree (phone varchar_pattern_ops);


--
-- Name: contact_contact_slug_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX contact_contact_slug_like ON contact_contact USING btree (slug varchar_pattern_ops);


--
-- Name: django_admin_log_content_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX django_admin_log_content_type_id ON django_admin_log USING btree (content_type_id);


--
-- Name: django_admin_log_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX django_admin_log_user_id ON django_admin_log USING btree (user_id);


--
-- Name: django_session_expire_date; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX django_session_expire_date ON django_session USING btree (expire_date);


--
-- Name: django_session_session_key_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX django_session_session_key_like ON django_session USING btree (session_key varchar_pattern_ops);


--
-- Name: djcelery_periodictask_crontab_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_periodictask_crontab_id ON djcelery_periodictask USING btree (crontab_id);


--
-- Name: djcelery_periodictask_interval_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_periodictask_interval_id ON djcelery_periodictask USING btree (interval_id);


--
-- Name: djcelery_periodictask_name_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_periodictask_name_like ON djcelery_periodictask USING btree (name varchar_pattern_ops);


--
-- Name: djcelery_taskstate_hidden; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_taskstate_hidden ON djcelery_taskstate USING btree (hidden);


--
-- Name: djcelery_taskstate_name; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_taskstate_name ON djcelery_taskstate USING btree (name);


--
-- Name: djcelery_taskstate_name_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_taskstate_name_like ON djcelery_taskstate USING btree (name varchar_pattern_ops);


--
-- Name: djcelery_taskstate_state; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_taskstate_state ON djcelery_taskstate USING btree (state);


--
-- Name: djcelery_taskstate_state_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_taskstate_state_like ON djcelery_taskstate USING btree (state varchar_pattern_ops);


--
-- Name: djcelery_taskstate_task_id_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_taskstate_task_id_like ON djcelery_taskstate USING btree (task_id varchar_pattern_ops);


--
-- Name: djcelery_taskstate_tstamp; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_taskstate_tstamp ON djcelery_taskstate USING btree (tstamp);


--
-- Name: djcelery_taskstate_worker_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_taskstate_worker_id ON djcelery_taskstate USING btree (worker_id);


--
-- Name: djcelery_workerstate_hostname_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_workerstate_hostname_like ON djcelery_workerstate USING btree (hostname varchar_pattern_ops);


--
-- Name: djcelery_workerstate_last_heartbeat; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX djcelery_workerstate_last_heartbeat ON djcelery_workerstate USING btree (last_heartbeat);


--
-- Name: incident_attack_created; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_attack_created ON incident_attack USING btree (created);


--
-- Name: incident_attack_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_attack_creator_id ON incident_attack USING btree (creator_id);


--
-- Name: incident_attack_incident_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_attack_incident_id ON incident_attack USING btree (incident_id);


--
-- Name: incident_attack_organization_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_attack_organization_id ON incident_attack USING btree (organization_id);


--
-- Name: incident_attack_subject; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_attack_subject ON incident_attack USING btree (subject);


--
-- Name: incident_attack_subject_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_attack_subject_like ON incident_attack USING btree (subject varchar_pattern_ops);


--
-- Name: incident_attack_target_ip; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_attack_target_ip ON incident_attack USING btree (target_ip);


--
-- Name: incident_category_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_category_creator_id ON incident_category USING btree (creator_id);


--
-- Name: incident_category_name; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_category_name ON incident_category USING btree (name);


--
-- Name: incident_category_name_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_category_name_like ON incident_category USING btree (name varchar_pattern_ops);


--
-- Name: incident_incident_aggregator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_aggregator_id ON incident_incident USING btree (aggregator_id);


--
-- Name: incident_incident_complainer; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_complainer ON incident_incident USING btree (complainer);


--
-- Name: incident_incident_complainer_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_complainer_like ON incident_incident USING btree (complainer varchar_pattern_ops);


--
-- Name: incident_incident_created; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_created ON incident_incident USING btree (created);


--
-- Name: incident_incident_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_creator_id ON incident_incident USING btree (creator_id);


--
-- Name: incident_incident_notified; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_notified ON incident_incident USING btree (notified);


--
-- Name: incident_incident_organization_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_organization_id ON incident_incident USING btree (organization_id);


--
-- Name: incident_incident_parent_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_parent_id ON incident_incident USING btree (parent_id);


--
-- Name: incident_incident_queue; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_queue ON incident_incident USING btree (queue);


--
-- Name: incident_incident_resolved; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_resolved ON incident_incident USING btree (resolved);


--
-- Name: incident_incident_rt_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_rt_id ON incident_incident USING btree (rt_id);


--
-- Name: incident_incident_source_ip; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_source_ip ON incident_incident USING btree (source_ip);


--
-- Name: incident_incident_status; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_status ON incident_incident USING btree (status);


--
-- Name: incident_incident_subject; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_subject ON incident_incident USING btree (subject);


--
-- Name: incident_incident_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_incident_type_id ON incident_incident USING btree (type_id);


--
-- Name: incident_type_category_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_type_category_id ON incident_type USING btree (category_id);


--
-- Name: incident_type_created; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_type_created ON incident_type USING btree (created);


--
-- Name: incident_type_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_type_creator_id ON incident_type USING btree (creator_id);


--
-- Name: incident_type_name; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_type_name ON incident_type USING btree (name);


--
-- Name: incident_type_name_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incident_type_name_like ON incident_type USING btree (name varchar_pattern_ops);


--
-- Name: incidentparser_historicalparser_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_historicalparser_creator_id ON incidentparser_historicalparser USING btree (creator_id);


--
-- Name: incidentparser_historicalparser_history_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_historicalparser_history_user_id ON incidentparser_historicalparser USING btree (history_user_id);


--
-- Name: incidentparser_historicalparser_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_historicalparser_id ON incidentparser_historicalparser USING btree (id);


--
-- Name: incidentparser_historicalparser_slug; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_historicalparser_slug ON incidentparser_historicalparser USING btree (slug);


--
-- Name: incidentparser_historicalparser_slug_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_historicalparser_slug_like ON incidentparser_historicalparser USING btree (slug varchar_pattern_ops);


--
-- Name: incidentparser_historicalparser_title; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_historicalparser_title ON incidentparser_historicalparser USING btree (title);


--
-- Name: incidentparser_historicalparser_title_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_historicalparser_title_like ON incidentparser_historicalparser USING btree (title varchar_pattern_ops);


--
-- Name: incidentparser_historicalparser_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_historicalparser_type_id ON incidentparser_historicalparser USING btree (type_id);


--
-- Name: incidentparser_incidentparser_incident_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_incidentparser_incident_id ON incidentparser_incidentparser USING btree (incident_id);


--
-- Name: incidentparser_incidentparser_parser_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_incidentparser_parser_id ON incidentparser_incidentparser USING btree (parser_id);


--
-- Name: incidentparser_incidentparser_task_id_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_incidentparser_task_id_like ON incidentparser_incidentparser USING btree (task_id varchar_pattern_ops);


--
-- Name: incidentparser_parser_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_parser_creator_id ON incidentparser_parser USING btree (creator_id);


--
-- Name: incidentparser_parser_slug_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_parser_slug_like ON incidentparser_parser USING btree (slug varchar_pattern_ops);


--
-- Name: incidentparser_parser_title_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_parser_title_like ON incidentparser_parser USING btree (title varchar_pattern_ops);


--
-- Name: incidentparser_parser_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX incidentparser_parser_type_id ON incidentparser_parser USING btree (type_id);


--
-- Name: network_network_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX network_network_creator_id ON network_network USING btree (creator_id);


--
-- Name: network_network_organization_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX network_network_organization_id ON network_network USING btree (organization_id);


--
-- Name: notify_notification_subscription_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX notify_notification_subscription_id ON notify_notification USING btree (subscription_id);


--
-- Name: notify_notificationtype_content_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX notify_notificationtype_content_type_id ON notify_notificationtype USING btree (content_type_id);


--
-- Name: notify_notificationtype_key_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX notify_notificationtype_key_like ON notify_notificationtype USING btree (key varchar_pattern_ops);


--
-- Name: notify_settings_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX notify_settings_user_id ON notify_settings USING btree (user_id);


--
-- Name: notify_subscription_latest_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX notify_subscription_latest_id ON notify_subscription USING btree (latest_id);


--
-- Name: notify_subscription_notification_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX notify_subscription_notification_type_id ON notify_subscription USING btree (notification_type_id);


--
-- Name: notify_subscription_notification_type_id_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX notify_subscription_notification_type_id_like ON notify_subscription USING btree (notification_type_id varchar_pattern_ops);


--
-- Name: notify_subscription_settings_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX notify_subscription_settings_id ON notify_subscription USING btree (settings_id);


--
-- Name: organization_organization_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_creator_id ON organization_organization USING btree (creator_id);


--
-- Name: organization_organization_level; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_level ON organization_organization USING btree (level);


--
-- Name: organization_organization_lft; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_lft ON organization_organization USING btree (lft);


--
-- Name: organization_organization_parent_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_parent_id ON organization_organization USING btree (parent_id);


--
-- Name: organization_organization_rght; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_rght ON organization_organization USING btree (rght);


--
-- Name: organization_organization_slug_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_slug_like ON organization_organization USING btree (slug varchar_pattern_ops);


--
-- Name: organization_organization_state; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_state ON organization_organization USING btree (state);


--
-- Name: organization_organization_state_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_state_like ON organization_organization USING btree (state varchar_pattern_ops);


--
-- Name: organization_organization_title_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_title_like ON organization_organization USING btree (title varchar_pattern_ops);


--
-- Name: organization_organization_tree_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_organization_tree_id ON organization_organization USING btree (tree_id);


--
-- Name: organization_permission_creator_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_permission_creator_id ON organization_permission USING btree (creator_id);


--
-- Name: organization_permission_organization_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_permission_organization_id ON organization_permission USING btree (organization_id);


--
-- Name: organization_permission_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX organization_permission_user_id ON organization_permission USING btree (user_id);


--
-- Name: queue_incidents_idx; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX queue_incidents_idx ON incident_incident USING btree (queue) WHERE (parent_id IS NOT NULL);


--
-- Name: shibboleth_accessdenied_login_date; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX shibboleth_accessdenied_login_date ON shibboleth_accessdenied USING btree (login_date);


--
-- Name: thumbnail_kvstore_key_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX thumbnail_kvstore_key_like ON thumbnail_kvstore USING btree (key varchar_pattern_ops);


--
-- Name: whitelist_whitelist_ip_network_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX whitelist_whitelist_ip_network_like ON whitelist_whitelist USING btree (ip_network varchar_pattern_ops);


--
-- Name: whitelist_whitelisttime_whitelist_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX whitelist_whitelisttime_whitelist_id ON whitelist_whitelisttime USING btree (whitelist_id);


--
-- Name: wiki_article_group_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_article_group_id ON wiki_article USING btree (group_id);


--
-- Name: wiki_article_owner_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_article_owner_id ON wiki_article USING btree (owner_id);


--
-- Name: wiki_articleforobject_article_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_articleforobject_article_id ON wiki_articleforobject USING btree (article_id);


--
-- Name: wiki_articleforobject_content_type_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_articleforobject_content_type_id ON wiki_articleforobject USING btree (content_type_id);


--
-- Name: wiki_articleplugin_article_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_articleplugin_article_id ON wiki_articleplugin USING btree (article_id);


--
-- Name: wiki_articlerevision_article_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_articlerevision_article_id ON wiki_articlerevision USING btree (article_id);


--
-- Name: wiki_articlerevision_previous_revision_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_articlerevision_previous_revision_id ON wiki_articlerevision USING btree (previous_revision_id);


--
-- Name: wiki_articlerevision_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_articlerevision_user_id ON wiki_articlerevision USING btree (user_id);


--
-- Name: wiki_attachmentrevision_attachment_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_attachmentrevision_attachment_id ON wiki_attachmentrevision USING btree (attachment_id);


--
-- Name: wiki_attachmentrevision_previous_revision_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_attachmentrevision_previous_revision_id ON wiki_attachmentrevision USING btree (previous_revision_id);


--
-- Name: wiki_attachmentrevision_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_attachmentrevision_user_id ON wiki_attachmentrevision USING btree (user_id);


--
-- Name: wiki_reusableplugin_articles_article_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_reusableplugin_articles_article_id ON wiki_reusableplugin_articles USING btree (article_id);


--
-- Name: wiki_reusableplugin_articles_reusableplugin_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_reusableplugin_articles_reusableplugin_id ON wiki_reusableplugin_articles USING btree (reusableplugin_id);


--
-- Name: wiki_revisionpluginrevision_plugin_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_revisionpluginrevision_plugin_id ON wiki_revisionpluginrevision USING btree (plugin_id);


--
-- Name: wiki_revisionpluginrevision_previous_revision_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_revisionpluginrevision_previous_revision_id ON wiki_revisionpluginrevision USING btree (previous_revision_id);


--
-- Name: wiki_revisionpluginrevision_user_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_revisionpluginrevision_user_id ON wiki_revisionpluginrevision USING btree (user_id);


--
-- Name: wiki_simpleplugin_article_revision_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_simpleplugin_article_revision_id ON wiki_simpleplugin USING btree (article_revision_id);


--
-- Name: wiki_urlpath_article_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_article_id ON wiki_urlpath USING btree (article_id);


--
-- Name: wiki_urlpath_level; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_level ON wiki_urlpath USING btree (level);


--
-- Name: wiki_urlpath_lft; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_lft ON wiki_urlpath USING btree (lft);


--
-- Name: wiki_urlpath_parent_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_parent_id ON wiki_urlpath USING btree (parent_id);


--
-- Name: wiki_urlpath_rght; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_rght ON wiki_urlpath USING btree (rght);


--
-- Name: wiki_urlpath_site_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_site_id ON wiki_urlpath USING btree (site_id);


--
-- Name: wiki_urlpath_slug; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_slug ON wiki_urlpath USING btree (slug);


--
-- Name: wiki_urlpath_slug_like; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_slug_like ON wiki_urlpath USING btree (slug varchar_pattern_ops);


--
-- Name: wiki_urlpath_tree_id; Type: INDEX; Schema: public; Owner: sgis; Tablespace: 
--

CREATE INDEX wiki_urlpath_tree_id ON wiki_urlpath USING btree (tree_id);


--
-- Name: action_object_content_type_id_refs_id_6f0ab83d91e6073f; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY actstream_action
    ADD CONSTRAINT action_object_content_type_id_refs_id_6f0ab83d91e6073f FOREIGN KEY (action_object_content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: actor_content_type_id_refs_id_6f0ab83d91e6073f; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY actstream_action
    ADD CONSTRAINT actor_content_type_id_refs_id_6f0ab83d91e6073f FOREIGN KEY (actor_content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: aggregator_id_refs_rt_id_34059cb6b7859247; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_incident
    ADD CONSTRAINT aggregator_id_refs_rt_id_34059cb6b7859247 FOREIGN KEY (aggregator_id) REFERENCES incident_incident(rt_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: article_id_refs_id_1698e37305099436; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articleforobject
    ADD CONSTRAINT article_id_refs_id_1698e37305099436 FOREIGN KEY (article_id) REFERENCES wiki_article(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: article_id_refs_id_23bd80e7971759c9; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_urlpath
    ADD CONSTRAINT article_id_refs_id_23bd80e7971759c9 FOREIGN KEY (article_id) REFERENCES wiki_article(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: article_id_refs_id_5a3b45ce5c88570a; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articlerevision
    ADD CONSTRAINT article_id_refs_id_5a3b45ce5c88570a FOREIGN KEY (article_id) REFERENCES wiki_article(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: article_id_refs_id_64fa106f92c648ca; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articleplugin
    ADD CONSTRAINT article_id_refs_id_64fa106f92c648ca FOREIGN KEY (article_id) REFERENCES wiki_article(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: article_id_refs_id_854477c2f51faad; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_reusableplugin_articles
    ADD CONSTRAINT article_id_refs_id_854477c2f51faad FOREIGN KEY (article_id) REFERENCES wiki_article(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: article_revision_id_refs_id_2252033b6df37b12; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_simpleplugin
    ADD CONSTRAINT article_revision_id_refs_id_2252033b6df37b12 FOREIGN KEY (article_revision_id) REFERENCES wiki_articlerevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: articleplugin_ptr_id_refs_id_2a5c48de4ca661fd; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_reusableplugin
    ADD CONSTRAINT articleplugin_ptr_id_refs_id_2a5c48de4ca661fd FOREIGN KEY (articleplugin_ptr_id) REFERENCES wiki_articleplugin(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: articleplugin_ptr_id_refs_id_2b8f815fcac31401; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_revisionplugin
    ADD CONSTRAINT articleplugin_ptr_id_refs_id_2b8f815fcac31401 FOREIGN KEY (articleplugin_ptr_id) REFERENCES wiki_articleplugin(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: articleplugin_ptr_id_refs_id_6704e8c7a25cbfd2; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_simpleplugin
    ADD CONSTRAINT articleplugin_ptr_id_refs_id_6704e8c7a25cbfd2 FOREIGN KEY (articleplugin_ptr_id) REFERENCES wiki_articleplugin(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: articleplugin_ptr_id_refs_id_7b2f9df4cbce00e3; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articlesubscription
    ADD CONSTRAINT articleplugin_ptr_id_refs_id_7b2f9df4cbce00e3 FOREIGN KEY (articleplugin_ptr_id) REFERENCES wiki_articleplugin(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: attachment_id_refs_reusableplugin_ptr_id_33d8cf1f640583da; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_attachmentrevision
    ADD CONSTRAINT attachment_id_refs_reusableplugin_ptr_id_33d8cf1f640583da FOREIGN KEY (attachment_id) REFERENCES wiki_attachment(reusableplugin_ptr_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: attachment_id_refs_reusableplugin_ptr_id_7d7709f10ca1a124; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY attachments_attachmentrevision
    ADD CONSTRAINT attachment_id_refs_reusableplugin_ptr_id_7d7709f10ca1a124 FOREIGN KEY (attachment_id) REFERENCES attachments_attachment(reusableplugin_ptr_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_group_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_user_groups_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_user_groups
    ADD CONSTRAINT auth_user_groups_group_id_fkey FOREIGN KEY (group_id) REFERENCES auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_user_user_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: category_id_refs_id_469080d4d51668dd; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_type
    ADD CONSTRAINT category_id_refs_id_469080d4d51668dd FOREIGN KEY (category_id) REFERENCES incident_category(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: contact_id_refs_id_4430041e7950e708; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY contact_contact_organizations
    ADD CONSTRAINT contact_id_refs_id_4430041e7950e708 FOREIGN KEY (contact_id) REFERENCES contact_contact(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: content_type_id_refs_id_45b2c87143220e98; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY actstream_follow
    ADD CONSTRAINT content_type_id_refs_id_45b2c87143220e98 FOREIGN KEY (content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: content_type_id_refs_id_4919de6f2478378; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_notificationtype
    ADD CONSTRAINT content_type_id_refs_id_4919de6f2478378 FOREIGN KEY (content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: content_type_id_refs_id_6b30567037828764; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articleforobject
    ADD CONSTRAINT content_type_id_refs_id_6b30567037828764 FOREIGN KEY (content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: content_type_id_refs_id_d043b34a; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_permission
    ADD CONSTRAINT content_type_id_refs_id_d043b34a FOREIGN KEY (content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_192e609aae922142; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY organization_permission
    ADD CONSTRAINT creator_id_refs_id_192e609aae922142 FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_1cf960c000b2a790; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY account_profile
    ADD CONSTRAINT creator_id_refs_id_1cf960c000b2a790 FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_1da0b2dc1cf08262; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_attack
    ADD CONSTRAINT creator_id_refs_id_1da0b2dc1cf08262 FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_29cc8f7d2b2b99f2; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY contact_contact
    ADD CONSTRAINT creator_id_refs_id_29cc8f7d2b2b99f2 FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_32bc0d057746e67c; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_type
    ADD CONSTRAINT creator_id_refs_id_32bc0d057746e67c FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_3ea10ac98dd024f6; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY network_network
    ADD CONSTRAINT creator_id_refs_id_3ea10ac98dd024f6 FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_5030c1be2a391874; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY organization_organization
    ADD CONSTRAINT creator_id_refs_id_5030c1be2a391874 FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_51e362ea3339ddcc; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_category
    ADD CONSTRAINT creator_id_refs_id_51e362ea3339ddcc FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_5eb5a4b6106e7c02; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_incident
    ADD CONSTRAINT creator_id_refs_id_5eb5a4b6106e7c02 FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: creator_id_refs_id_79d59ee2eae0222a; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incidentparser_parser
    ADD CONSTRAINT creator_id_refs_id_79d59ee2eae0222a FOREIGN KEY (creator_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: crontab_id_refs_id_2c92a393ebff5e74; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY djcelery_periodictask
    ADD CONSTRAINT crontab_id_refs_id_2c92a393ebff5e74 FOREIGN KEY (crontab_id) REFERENCES djcelery_crontabschedule(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: current_revision_id_refs_id_1d8d320ebafac304; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_article
    ADD CONSTRAINT current_revision_id_refs_id_1d8d320ebafac304 FOREIGN KEY (current_revision_id) REFERENCES wiki_articlerevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: current_revision_id_refs_id_2732d4b244938e26; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_revisionplugin
    ADD CONSTRAINT current_revision_id_refs_id_2732d4b244938e26 FOREIGN KEY (current_revision_id) REFERENCES wiki_revisionpluginrevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: current_revision_id_refs_id_368bbd641357d552; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY attachments_attachment
    ADD CONSTRAINT current_revision_id_refs_id_368bbd641357d552 FOREIGN KEY (current_revision_id) REFERENCES attachments_attachmentrevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: current_revision_id_refs_id_66561e6e2198feb4; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_attachment
    ADD CONSTRAINT current_revision_id_refs_id_66561e6e2198feb4 FOREIGN KEY (current_revision_id) REFERENCES wiki_attachmentrevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: django_admin_log_content_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY django_admin_log
    ADD CONSTRAINT django_admin_log_content_type_id_fkey FOREIGN KEY (content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: django_admin_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY django_admin_log
    ADD CONSTRAINT django_admin_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: group_id_refs_id_10e2d3dd108bfee4; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_article
    ADD CONSTRAINT group_id_refs_id_10e2d3dd108bfee4 FOREIGN KEY (group_id) REFERENCES auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: group_id_refs_id_f4b32aac; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_group_permissions
    ADD CONSTRAINT group_id_refs_id_f4b32aac FOREIGN KEY (group_id) REFERENCES auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: history_user_id_refs_id_346429003a1a1b4; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incidentparser_historicalparser
    ADD CONSTRAINT history_user_id_refs_id_346429003a1a1b4 FOREIGN KEY (history_user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: home_id_refs_id_d516297ee86fc57; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY account_profile
    ADD CONSTRAINT home_id_refs_id_d516297ee86fc57 FOREIGN KEY (home_id) REFERENCES organization_organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_id_refs_rt_id_6c5b299298a0c55; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_attack
    ADD CONSTRAINT incident_id_refs_rt_id_6c5b299298a0c55 FOREIGN KEY (incident_id) REFERENCES incident_incident(rt_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_summary_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_summary
    ADD CONSTRAINT incident_summary_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES organization_organization(id);


--
-- Name: incident_summary_users_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_summary_users
    ADD CONSTRAINT incident_summary_users_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES organization_organization(id);


--
-- Name: incident_summary_users_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_summary_users
    ADD CONSTRAINT incident_summary_users_user_id_fkey FOREIGN KEY (user_id) REFERENCES account_profile(user_id);


--
-- Name: interval_id_refs_id_672c7616f2054349; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY djcelery_periodictask
    ADD CONSTRAINT interval_id_refs_id_672c7616f2054349 FOREIGN KEY (interval_id) REFERENCES djcelery_intervalschedule(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: latest_id_refs_id_371d5b2c0e279e4d; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_subscription
    ADD CONSTRAINT latest_id_refs_id_371d5b2c0e279e4d FOREIGN KEY (latest_id) REFERENCES notify_notification(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: notification_type_id_refs_key_25426c9bbaa41a19; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_subscription
    ADD CONSTRAINT notification_type_id_refs_key_25426c9bbaa41a19 FOREIGN KEY (notification_type_id) REFERENCES notify_notificationtype(key) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: organization_id_refs_id_10c83415bc0bc73a; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY contact_contact_organizations
    ADD CONSTRAINT organization_id_refs_id_10c83415bc0bc73a FOREIGN KEY (organization_id) REFERENCES organization_organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: organization_id_refs_id_2d70d288b5eef1af; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY network_network
    ADD CONSTRAINT organization_id_refs_id_2d70d288b5eef1af FOREIGN KEY (organization_id) REFERENCES organization_organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: organization_id_refs_id_4509c94e099bae9d; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY organization_permission
    ADD CONSTRAINT organization_id_refs_id_4509c94e099bae9d FOREIGN KEY (organization_id) REFERENCES organization_organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: organization_id_refs_id_6517994788590729; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_attack
    ADD CONSTRAINT organization_id_refs_id_6517994788590729 FOREIGN KEY (organization_id) REFERENCES organization_organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: organization_id_refs_id_69b91d7e21ea325d; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_incident
    ADD CONSTRAINT organization_id_refs_id_69b91d7e21ea325d FOREIGN KEY (organization_id) REFERENCES organization_organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: owner_id_refs_id_18073b359e14b583; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_article
    ADD CONSTRAINT owner_id_refs_id_18073b359e14b583 FOREIGN KEY (owner_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: parent_id_refs_id_369eb34ab649c98b; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY organization_organization
    ADD CONSTRAINT parent_id_refs_id_369eb34ab649c98b FOREIGN KEY (parent_id) REFERENCES organization_organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: parent_id_refs_id_62afe7c752d1e703; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_urlpath
    ADD CONSTRAINT parent_id_refs_id_62afe7c752d1e703 FOREIGN KEY (parent_id) REFERENCES wiki_urlpath(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: parser_id_refs_id_2792ea6ba34d21bf; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incidentparser_incidentparser
    ADD CONSTRAINT parser_id_refs_id_2792ea6ba34d21bf FOREIGN KEY (parser_id) REFERENCES incidentparser_parser(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: plugin_id_refs_articleplugin_ptr_id_3e044eb541bbc69c; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_revisionpluginrevision
    ADD CONSTRAINT plugin_id_refs_articleplugin_ptr_id_3e044eb541bbc69c FOREIGN KEY (plugin_id) REFERENCES wiki_revisionplugin(articleplugin_ptr_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: previous_revision_id_refs_id_2319a7ecf6145dc3; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY attachments_attachmentrevision
    ADD CONSTRAINT previous_revision_id_refs_id_2319a7ecf6145dc3 FOREIGN KEY (previous_revision_id) REFERENCES attachments_attachmentrevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: previous_revision_id_refs_id_3348918678fffe43; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_revisionpluginrevision
    ADD CONSTRAINT previous_revision_id_refs_id_3348918678fffe43 FOREIGN KEY (previous_revision_id) REFERENCES wiki_revisionpluginrevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: previous_revision_id_refs_id_5521ecec0041bbf5; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_attachmentrevision
    ADD CONSTRAINT previous_revision_id_refs_id_5521ecec0041bbf5 FOREIGN KEY (previous_revision_id) REFERENCES wiki_attachmentrevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: previous_revision_id_refs_id_7c6fe338a951e36b; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articlerevision
    ADD CONSTRAINT previous_revision_id_refs_id_7c6fe338a951e36b FOREIGN KEY (previous_revision_id) REFERENCES wiki_articlerevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: reusableplugin_id_refs_articleplugin_ptr_id_496cabe744b45e30; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_reusableplugin_articles
    ADD CONSTRAINT reusableplugin_id_refs_articleplugin_ptr_id_496cabe744b45e30 FOREIGN KEY (reusableplugin_id) REFERENCES wiki_reusableplugin(articleplugin_ptr_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: reusableplugin_ptr_id_refs_articleplugin_ptr_id_14d299f4831e2f8; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY attachments_attachment
    ADD CONSTRAINT reusableplugin_ptr_id_refs_articleplugin_ptr_id_14d299f4831e2f8 FOREIGN KEY (reusableplugin_ptr_id) REFERENCES wiki_reusableplugin(articleplugin_ptr_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: reusableplugin_ptr_id_refs_articleplugin_ptr_id_79d179a16640ce8; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_attachment
    ADD CONSTRAINT reusableplugin_ptr_id_refs_articleplugin_ptr_id_79d179a16640ce8 FOREIGN KEY (reusableplugin_ptr_id) REFERENCES wiki_reusableplugin(articleplugin_ptr_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: revisionplugin_ptr_id_refs_articleplugin_ptr_id_1a20f885fc4fe20; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_image
    ADD CONSTRAINT revisionplugin_ptr_id_refs_articleplugin_ptr_id_1a20f885fc4fe20 FOREIGN KEY (revisionplugin_ptr_id) REFERENCES wiki_revisionplugin(articleplugin_ptr_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: revisionplugin_ptr_id_refs_articleplugin_ptr_id_4fda8ce32471fca; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY images_image
    ADD CONSTRAINT revisionplugin_ptr_id_refs_articleplugin_ptr_id_4fda8ce32471fca FOREIGN KEY (revisionplugin_ptr_id) REFERENCES wiki_revisionplugin(articleplugin_ptr_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: revisionpluginrevision_ptr_id_refs_id_5da3ee545b9fc791; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_imagerevision
    ADD CONSTRAINT revisionpluginrevision_ptr_id_refs_id_5da3ee545b9fc791 FOREIGN KEY (revisionpluginrevision_ptr_id) REFERENCES wiki_revisionpluginrevision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: settings_id_refs_id_2b8d6d653b7225d5; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_subscription
    ADD CONSTRAINT settings_id_refs_id_2b8d6d653b7225d5 FOREIGN KEY (settings_id) REFERENCES notify_settings(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: site_id_refs_id_462d2bc7f4bbaaa2; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_urlpath
    ADD CONSTRAINT site_id_refs_id_462d2bc7f4bbaaa2 FOREIGN KEY (site_id) REFERENCES django_site(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: subscription_id_refs_id_7a99ebc5baf93d4f; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_notification
    ADD CONSTRAINT subscription_id_refs_id_7a99ebc5baf93d4f FOREIGN KEY (subscription_id) REFERENCES notify_subscription(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: subscription_ptr_id_refs_id_4ec3f6dbae89f475; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articlesubscription
    ADD CONSTRAINT subscription_ptr_id_refs_id_4ec3f6dbae89f475 FOREIGN KEY (subscription_ptr_id) REFERENCES notify_subscription(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: target_content_type_id_refs_id_6f0ab83d91e6073f; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY actstream_action
    ADD CONSTRAINT target_content_type_id_refs_id_6f0ab83d91e6073f FOREIGN KEY (target_content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: type_id_refs_id_52dfcb65078a2d2d; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incidentparser_parser
    ADD CONSTRAINT type_id_refs_id_52dfcb65078a2d2d FOREIGN KEY (type_id) REFERENCES incident_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: type_id_refs_id_702154540337997b; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY incident_incident
    ADD CONSTRAINT type_id_refs_id_702154540337997b FOREIGN KEY (type_id) REFERENCES incident_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_18903908bb0d8109; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY attachments_attachmentrevision
    ADD CONSTRAINT user_id_refs_id_18903908bb0d8109 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_192e609aae922142; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY organization_permission
    ADD CONSTRAINT user_id_refs_id_192e609aae922142 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_1cf960c000b2a790; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY account_profile
    ADD CONSTRAINT user_id_refs_id_1cf960c000b2a790 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_21540d2c32d8f395; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_revisionpluginrevision
    ADD CONSTRAINT user_id_refs_id_21540d2c32d8f395 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_2822eb682eaca84c; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_attachmentrevision
    ADD CONSTRAINT user_id_refs_id_2822eb682eaca84c FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_2e6a6a1d9a2911e6; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY notify_settings
    ADD CONSTRAINT user_id_refs_id_2e6a6a1d9a2911e6 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_40c41112; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_user_groups
    ADD CONSTRAINT user_id_refs_id_40c41112 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_4dc23c39; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY auth_user_user_permissions
    ADD CONSTRAINT user_id_refs_id_4dc23c39 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_672c6e4dfbb26714; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY wiki_articlerevision
    ADD CONSTRAINT user_id_refs_id_672c6e4dfbb26714 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_88c60c63d8a2214; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY actstream_follow
    ADD CONSTRAINT user_id_refs_id_88c60c63d8a2214 FOREIGN KEY (user_id) REFERENCES auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: whitelist_whitelisttime_whitelist_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY whitelist_whitelisttime
    ADD CONSTRAINT whitelist_whitelisttime_whitelist_id_fkey FOREIGN KEY (whitelist_id) REFERENCES whitelist_whitelist(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: worker_id_refs_id_13af6e2204e3453a; Type: FK CONSTRAINT; Schema: public; Owner: sgis
--

ALTER TABLE ONLY djcelery_taskstate
    ADD CONSTRAINT worker_id_refs_id_13af6e2204e3453a FOREIGN KEY (worker_id) REFERENCES djcelery_workerstate(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;
GRANT USAGE ON SCHEMA public TO sgis_readonly;


--
-- Name: account_profile; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE account_profile FROM PUBLIC;
REVOKE ALL ON TABLE account_profile FROM sgis;
GRANT ALL ON TABLE account_profile TO sgis;
GRANT SELECT ON TABLE account_profile TO sgis_readonly;


--
-- Name: actstream_action; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE actstream_action FROM PUBLIC;
REVOKE ALL ON TABLE actstream_action FROM sgis;
GRANT ALL ON TABLE actstream_action TO sgis;
GRANT SELECT ON TABLE actstream_action TO sgis_readonly;


--
-- Name: actstream_action_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE actstream_action_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE actstream_action_id_seq FROM sgis;
GRANT ALL ON SEQUENCE actstream_action_id_seq TO sgis;
GRANT SELECT ON SEQUENCE actstream_action_id_seq TO sgis_readonly;


--
-- Name: actstream_follow; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE actstream_follow FROM PUBLIC;
REVOKE ALL ON TABLE actstream_follow FROM sgis;
GRANT ALL ON TABLE actstream_follow TO sgis;
GRANT SELECT ON TABLE actstream_follow TO sgis_readonly;


--
-- Name: actstream_follow_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE actstream_follow_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE actstream_follow_id_seq FROM sgis;
GRANT ALL ON SEQUENCE actstream_follow_id_seq TO sgis;
GRANT SELECT ON SEQUENCE actstream_follow_id_seq TO sgis_readonly;


--
-- Name: attachments_attachment; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE attachments_attachment FROM PUBLIC;
REVOKE ALL ON TABLE attachments_attachment FROM sgis;
GRANT ALL ON TABLE attachments_attachment TO sgis;
GRANT SELECT ON TABLE attachments_attachment TO sgis_readonly;


--
-- Name: attachments_attachmentrevision; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE attachments_attachmentrevision FROM PUBLIC;
REVOKE ALL ON TABLE attachments_attachmentrevision FROM sgis;
GRANT ALL ON TABLE attachments_attachmentrevision TO sgis;
GRANT SELECT ON TABLE attachments_attachmentrevision TO sgis_readonly;


--
-- Name: attachments_attachmentrevision_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE attachments_attachmentrevision_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE attachments_attachmentrevision_id_seq FROM sgis;
GRANT ALL ON SEQUENCE attachments_attachmentrevision_id_seq TO sgis;
GRANT SELECT ON SEQUENCE attachments_attachmentrevision_id_seq TO sgis_readonly;


--
-- Name: auth_group; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE auth_group FROM PUBLIC;
REVOKE ALL ON TABLE auth_group FROM sgis;
GRANT ALL ON TABLE auth_group TO sgis;
GRANT SELECT ON TABLE auth_group TO sgis_readonly;


--
-- Name: auth_group_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE auth_group_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE auth_group_id_seq FROM sgis;
GRANT ALL ON SEQUENCE auth_group_id_seq TO sgis;
GRANT SELECT ON SEQUENCE auth_group_id_seq TO sgis_readonly;


--
-- Name: auth_group_permissions; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE auth_group_permissions FROM PUBLIC;
REVOKE ALL ON TABLE auth_group_permissions FROM sgis;
GRANT ALL ON TABLE auth_group_permissions TO sgis;
GRANT SELECT ON TABLE auth_group_permissions TO sgis_readonly;


--
-- Name: auth_group_permissions_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE auth_group_permissions_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE auth_group_permissions_id_seq FROM sgis;
GRANT ALL ON SEQUENCE auth_group_permissions_id_seq TO sgis;
GRANT SELECT ON SEQUENCE auth_group_permissions_id_seq TO sgis_readonly;


--
-- Name: auth_permission; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE auth_permission FROM PUBLIC;
REVOKE ALL ON TABLE auth_permission FROM sgis;
GRANT ALL ON TABLE auth_permission TO sgis;
GRANT SELECT ON TABLE auth_permission TO sgis_readonly;


--
-- Name: auth_permission_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE auth_permission_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE auth_permission_id_seq FROM sgis;
GRANT ALL ON SEQUENCE auth_permission_id_seq TO sgis;
GRANT SELECT ON SEQUENCE auth_permission_id_seq TO sgis_readonly;


--
-- Name: auth_user; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE auth_user FROM PUBLIC;
REVOKE ALL ON TABLE auth_user FROM sgis;
GRANT ALL ON TABLE auth_user TO sgis;
GRANT SELECT ON TABLE auth_user TO sgis_readonly;


--
-- Name: auth_user_groups; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE auth_user_groups FROM PUBLIC;
REVOKE ALL ON TABLE auth_user_groups FROM sgis;
GRANT ALL ON TABLE auth_user_groups TO sgis;
GRANT SELECT ON TABLE auth_user_groups TO sgis_readonly;


--
-- Name: auth_user_groups_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE auth_user_groups_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE auth_user_groups_id_seq FROM sgis;
GRANT ALL ON SEQUENCE auth_user_groups_id_seq TO sgis;
GRANT SELECT ON SEQUENCE auth_user_groups_id_seq TO sgis_readonly;


--
-- Name: auth_user_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE auth_user_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE auth_user_id_seq FROM sgis;
GRANT ALL ON SEQUENCE auth_user_id_seq TO sgis;
GRANT SELECT ON SEQUENCE auth_user_id_seq TO sgis_readonly;


--
-- Name: auth_user_user_permissions; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE auth_user_user_permissions FROM PUBLIC;
REVOKE ALL ON TABLE auth_user_user_permissions FROM sgis;
GRANT ALL ON TABLE auth_user_user_permissions TO sgis;
GRANT SELECT ON TABLE auth_user_user_permissions TO sgis_readonly;


--
-- Name: auth_user_user_permissions_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE auth_user_user_permissions_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE auth_user_user_permissions_id_seq FROM sgis;
GRANT ALL ON SEQUENCE auth_user_user_permissions_id_seq TO sgis;
GRANT SELECT ON SEQUENCE auth_user_user_permissions_id_seq TO sgis_readonly;


--
-- Name: celery_taskmeta; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE celery_taskmeta FROM PUBLIC;
REVOKE ALL ON TABLE celery_taskmeta FROM sgis;
GRANT ALL ON TABLE celery_taskmeta TO sgis;
GRANT SELECT ON TABLE celery_taskmeta TO sgis_readonly;


--
-- Name: celery_taskmeta_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE celery_taskmeta_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE celery_taskmeta_id_seq FROM sgis;
GRANT ALL ON SEQUENCE celery_taskmeta_id_seq TO sgis;
GRANT SELECT ON SEQUENCE celery_taskmeta_id_seq TO sgis_readonly;


--
-- Name: celery_tasksetmeta; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE celery_tasksetmeta FROM PUBLIC;
REVOKE ALL ON TABLE celery_tasksetmeta FROM sgis;
GRANT ALL ON TABLE celery_tasksetmeta TO sgis;
GRANT SELECT ON TABLE celery_tasksetmeta TO sgis_readonly;


--
-- Name: celery_tasksetmeta_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE celery_tasksetmeta_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE celery_tasksetmeta_id_seq FROM sgis;
GRANT ALL ON SEQUENCE celery_tasksetmeta_id_seq TO sgis;
GRANT SELECT ON SEQUENCE celery_tasksetmeta_id_seq TO sgis_readonly;


--
-- Name: contact_contact; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE contact_contact FROM PUBLIC;
REVOKE ALL ON TABLE contact_contact FROM sgis;
GRANT ALL ON TABLE contact_contact TO sgis;
GRANT SELECT ON TABLE contact_contact TO sgis_readonly;


--
-- Name: contact_contact_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE contact_contact_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE contact_contact_id_seq FROM sgis;
GRANT ALL ON SEQUENCE contact_contact_id_seq TO sgis;
GRANT SELECT ON SEQUENCE contact_contact_id_seq TO sgis_readonly;


--
-- Name: contact_contact_organizations; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE contact_contact_organizations FROM PUBLIC;
REVOKE ALL ON TABLE contact_contact_organizations FROM sgis;
GRANT ALL ON TABLE contact_contact_organizations TO sgis;
GRANT SELECT ON TABLE contact_contact_organizations TO sgis_readonly;


--
-- Name: contact_contact_organizations_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE contact_contact_organizations_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE contact_contact_organizations_id_seq FROM sgis;
GRANT ALL ON SEQUENCE contact_contact_organizations_id_seq TO sgis;
GRANT SELECT ON SEQUENCE contact_contact_organizations_id_seq TO sgis_readonly;


--
-- Name: django_admin_log; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE django_admin_log FROM PUBLIC;
REVOKE ALL ON TABLE django_admin_log FROM sgis;
GRANT ALL ON TABLE django_admin_log TO sgis;
GRANT SELECT ON TABLE django_admin_log TO sgis_readonly;


--
-- Name: django_admin_log_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE django_admin_log_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE django_admin_log_id_seq FROM sgis;
GRANT ALL ON SEQUENCE django_admin_log_id_seq TO sgis;
GRANT SELECT ON SEQUENCE django_admin_log_id_seq TO sgis_readonly;


--
-- Name: django_content_type; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE django_content_type FROM PUBLIC;
REVOKE ALL ON TABLE django_content_type FROM sgis;
GRANT ALL ON TABLE django_content_type TO sgis;
GRANT SELECT ON TABLE django_content_type TO sgis_readonly;


--
-- Name: django_content_type_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE django_content_type_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE django_content_type_id_seq FROM sgis;
GRANT ALL ON SEQUENCE django_content_type_id_seq TO sgis;
GRANT SELECT ON SEQUENCE django_content_type_id_seq TO sgis_readonly;


--
-- Name: django_session; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE django_session FROM PUBLIC;
REVOKE ALL ON TABLE django_session FROM sgis;
GRANT ALL ON TABLE django_session TO sgis;
GRANT SELECT ON TABLE django_session TO sgis_readonly;


--
-- Name: django_site; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE django_site FROM PUBLIC;
REVOKE ALL ON TABLE django_site FROM sgis;
GRANT ALL ON TABLE django_site TO sgis;
GRANT SELECT ON TABLE django_site TO sgis_readonly;


--
-- Name: django_site_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE django_site_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE django_site_id_seq FROM sgis;
GRANT ALL ON SEQUENCE django_site_id_seq TO sgis;
GRANT SELECT ON SEQUENCE django_site_id_seq TO sgis_readonly;


--
-- Name: djcelery_crontabschedule; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE djcelery_crontabschedule FROM PUBLIC;
REVOKE ALL ON TABLE djcelery_crontabschedule FROM sgis;
GRANT ALL ON TABLE djcelery_crontabschedule TO sgis;
GRANT SELECT ON TABLE djcelery_crontabschedule TO sgis_readonly;


--
-- Name: djcelery_crontabschedule_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE djcelery_crontabschedule_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE djcelery_crontabschedule_id_seq FROM sgis;
GRANT ALL ON SEQUENCE djcelery_crontabschedule_id_seq TO sgis;
GRANT SELECT ON SEQUENCE djcelery_crontabschedule_id_seq TO sgis_readonly;


--
-- Name: djcelery_intervalschedule; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE djcelery_intervalschedule FROM PUBLIC;
REVOKE ALL ON TABLE djcelery_intervalschedule FROM sgis;
GRANT ALL ON TABLE djcelery_intervalschedule TO sgis;
GRANT SELECT ON TABLE djcelery_intervalschedule TO sgis_readonly;


--
-- Name: djcelery_intervalschedule_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE djcelery_intervalschedule_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE djcelery_intervalschedule_id_seq FROM sgis;
GRANT ALL ON SEQUENCE djcelery_intervalschedule_id_seq TO sgis;
GRANT SELECT ON SEQUENCE djcelery_intervalschedule_id_seq TO sgis_readonly;


--
-- Name: djcelery_periodictask; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE djcelery_periodictask FROM PUBLIC;
REVOKE ALL ON TABLE djcelery_periodictask FROM sgis;
GRANT ALL ON TABLE djcelery_periodictask TO sgis;
GRANT SELECT ON TABLE djcelery_periodictask TO sgis_readonly;


--
-- Name: djcelery_periodictask_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE djcelery_periodictask_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE djcelery_periodictask_id_seq FROM sgis;
GRANT ALL ON SEQUENCE djcelery_periodictask_id_seq TO sgis;
GRANT SELECT ON SEQUENCE djcelery_periodictask_id_seq TO sgis_readonly;


--
-- Name: djcelery_periodictasks; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE djcelery_periodictasks FROM PUBLIC;
REVOKE ALL ON TABLE djcelery_periodictasks FROM sgis;
GRANT ALL ON TABLE djcelery_periodictasks TO sgis;
GRANT SELECT ON TABLE djcelery_periodictasks TO sgis_readonly;


--
-- Name: djcelery_taskstate; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE djcelery_taskstate FROM PUBLIC;
REVOKE ALL ON TABLE djcelery_taskstate FROM sgis;
GRANT ALL ON TABLE djcelery_taskstate TO sgis;
GRANT SELECT ON TABLE djcelery_taskstate TO sgis_readonly;


--
-- Name: djcelery_taskstate_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE djcelery_taskstate_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE djcelery_taskstate_id_seq FROM sgis;
GRANT ALL ON SEQUENCE djcelery_taskstate_id_seq TO sgis;
GRANT SELECT ON SEQUENCE djcelery_taskstate_id_seq TO sgis_readonly;


--
-- Name: djcelery_workerstate; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE djcelery_workerstate FROM PUBLIC;
REVOKE ALL ON TABLE djcelery_workerstate FROM sgis;
GRANT ALL ON TABLE djcelery_workerstate TO sgis;
GRANT SELECT ON TABLE djcelery_workerstate TO sgis_readonly;


--
-- Name: djcelery_workerstate_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE djcelery_workerstate_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE djcelery_workerstate_id_seq FROM sgis;
GRANT ALL ON SEQUENCE djcelery_workerstate_id_seq TO sgis;
GRANT SELECT ON SEQUENCE djcelery_workerstate_id_seq TO sgis_readonly;


--
-- Name: images_image; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE images_image FROM PUBLIC;
REVOKE ALL ON TABLE images_image FROM sgis;
GRANT ALL ON TABLE images_image TO sgis;
GRANT SELECT ON TABLE images_image TO sgis_readonly;


--
-- Name: incident_attack_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE incident_attack_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE incident_attack_id_seq FROM sgis;
GRANT ALL ON SEQUENCE incident_attack_id_seq TO sgis;
GRANT SELECT ON SEQUENCE incident_attack_id_seq TO sgis_readonly;


--
-- Name: incident_attack; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incident_attack FROM PUBLIC;
REVOKE ALL ON TABLE incident_attack FROM sgis;
GRANT ALL ON TABLE incident_attack TO sgis;
GRANT SELECT ON TABLE incident_attack TO sgis_readonly;


--
-- Name: incident_category; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incident_category FROM PUBLIC;
REVOKE ALL ON TABLE incident_category FROM sgis;
GRANT ALL ON TABLE incident_category TO sgis;
GRANT SELECT ON TABLE incident_category TO sgis_readonly;


--
-- Name: incident_category_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE incident_category_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE incident_category_id_seq FROM sgis;
GRANT ALL ON SEQUENCE incident_category_id_seq TO sgis;
GRANT SELECT ON SEQUENCE incident_category_id_seq TO sgis_readonly;


--
-- Name: incident_incident; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incident_incident FROM PUBLIC;
REVOKE ALL ON TABLE incident_incident FROM sgis;
GRANT ALL ON TABLE incident_incident TO sgis;
GRANT SELECT ON TABLE incident_incident TO sgis_readonly;


--
-- Name: incident_summary; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incident_summary FROM PUBLIC;
REVOKE ALL ON TABLE incident_summary FROM sgis;
GRANT ALL ON TABLE incident_summary TO sgis;
GRANT SELECT ON TABLE incident_summary TO sgis_readonly;


--
-- Name: incident_summary_users; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incident_summary_users FROM PUBLIC;
REVOKE ALL ON TABLE incident_summary_users FROM sgis;
GRANT ALL ON TABLE incident_summary_users TO sgis;
GRANT SELECT ON TABLE incident_summary_users TO sgis_readonly;


--
-- Name: organization_organization; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE organization_organization FROM PUBLIC;
REVOKE ALL ON TABLE organization_organization FROM sgis;
GRANT ALL ON TABLE organization_organization TO sgis;
GRANT SELECT ON TABLE organization_organization TO sgis_readonly;


--
-- Name: incident_summary_users_view; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incident_summary_users_view FROM PUBLIC;
REVOKE ALL ON TABLE incident_summary_users_view FROM sgis;
GRANT ALL ON TABLE incident_summary_users_view TO sgis;
GRANT SELECT ON TABLE incident_summary_users_view TO sgis_readonly;


--
-- Name: incident_type; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incident_type FROM PUBLIC;
REVOKE ALL ON TABLE incident_type FROM sgis;
GRANT ALL ON TABLE incident_type TO sgis;
GRANT SELECT ON TABLE incident_type TO sgis_readonly;


--
-- Name: incident_type_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE incident_type_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE incident_type_id_seq FROM sgis;
GRANT ALL ON SEQUENCE incident_type_id_seq TO sgis;
GRANT SELECT ON SEQUENCE incident_type_id_seq TO sgis_readonly;


--
-- Name: incidentparser_historicalparser; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incidentparser_historicalparser FROM PUBLIC;
REVOKE ALL ON TABLE incidentparser_historicalparser FROM sgis;
GRANT ALL ON TABLE incidentparser_historicalparser TO sgis;
GRANT SELECT ON TABLE incidentparser_historicalparser TO sgis_readonly;


--
-- Name: incidentparser_historicalparser_history_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE incidentparser_historicalparser_history_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE incidentparser_historicalparser_history_id_seq FROM sgis;
GRANT ALL ON SEQUENCE incidentparser_historicalparser_history_id_seq TO sgis;
GRANT SELECT ON SEQUENCE incidentparser_historicalparser_history_id_seq TO sgis_readonly;


--
-- Name: incidentparser_incidentparser; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incidentparser_incidentparser FROM PUBLIC;
REVOKE ALL ON TABLE incidentparser_incidentparser FROM sgis;
GRANT ALL ON TABLE incidentparser_incidentparser TO sgis;
GRANT SELECT ON TABLE incidentparser_incidentparser TO sgis_readonly;


--
-- Name: incidentparser_incidentparser_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE incidentparser_incidentparser_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE incidentparser_incidentparser_id_seq FROM sgis;
GRANT ALL ON SEQUENCE incidentparser_incidentparser_id_seq TO sgis;
GRANT SELECT ON SEQUENCE incidentparser_incidentparser_id_seq TO sgis_readonly;


--
-- Name: incidentparser_parser; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE incidentparser_parser FROM PUBLIC;
REVOKE ALL ON TABLE incidentparser_parser FROM sgis;
GRANT ALL ON TABLE incidentparser_parser TO sgis;
GRANT SELECT ON TABLE incidentparser_parser TO sgis_readonly;


--
-- Name: incidentparser_parser_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE incidentparser_parser_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE incidentparser_parser_id_seq FROM sgis;
GRANT ALL ON SEQUENCE incidentparser_parser_id_seq TO sgis;
GRANT SELECT ON SEQUENCE incidentparser_parser_id_seq TO sgis_readonly;


--
-- Name: network_network; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE network_network FROM PUBLIC;
REVOKE ALL ON TABLE network_network FROM sgis;
GRANT ALL ON TABLE network_network TO sgis;
GRANT SELECT ON TABLE network_network TO sgis_readonly;


--
-- Name: network_network_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE network_network_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE network_network_id_seq FROM sgis;
GRANT ALL ON SEQUENCE network_network_id_seq TO sgis;
GRANT SELECT ON SEQUENCE network_network_id_seq TO sgis_readonly;


--
-- Name: notify_notification; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE notify_notification FROM PUBLIC;
REVOKE ALL ON TABLE notify_notification FROM sgis;
GRANT ALL ON TABLE notify_notification TO sgis;
GRANT SELECT ON TABLE notify_notification TO sgis_readonly;


--
-- Name: notify_notification_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE notify_notification_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE notify_notification_id_seq FROM sgis;
GRANT ALL ON SEQUENCE notify_notification_id_seq TO sgis;
GRANT SELECT ON SEQUENCE notify_notification_id_seq TO sgis_readonly;


--
-- Name: notify_notificationtype; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE notify_notificationtype FROM PUBLIC;
REVOKE ALL ON TABLE notify_notificationtype FROM sgis;
GRANT ALL ON TABLE notify_notificationtype TO sgis;
GRANT SELECT ON TABLE notify_notificationtype TO sgis_readonly;


--
-- Name: notify_settings; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE notify_settings FROM PUBLIC;
REVOKE ALL ON TABLE notify_settings FROM sgis;
GRANT ALL ON TABLE notify_settings TO sgis;
GRANT SELECT ON TABLE notify_settings TO sgis_readonly;


--
-- Name: notify_settings_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE notify_settings_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE notify_settings_id_seq FROM sgis;
GRANT ALL ON SEQUENCE notify_settings_id_seq TO sgis;
GRANT SELECT ON SEQUENCE notify_settings_id_seq TO sgis_readonly;


--
-- Name: notify_subscription; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE notify_subscription FROM PUBLIC;
REVOKE ALL ON TABLE notify_subscription FROM sgis;
GRANT ALL ON TABLE notify_subscription TO sgis;
GRANT SELECT ON TABLE notify_subscription TO sgis_readonly;


--
-- Name: notify_subscription_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE notify_subscription_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE notify_subscription_id_seq FROM sgis;
GRANT ALL ON SEQUENCE notify_subscription_id_seq TO sgis;
GRANT SELECT ON SEQUENCE notify_subscription_id_seq TO sgis_readonly;


--
-- Name: organization_organization_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE organization_organization_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE organization_organization_id_seq FROM sgis;
GRANT ALL ON SEQUENCE organization_organization_id_seq TO sgis;
GRANT SELECT ON SEQUENCE organization_organization_id_seq TO sgis_readonly;


--
-- Name: organization_permission; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE organization_permission FROM PUBLIC;
REVOKE ALL ON TABLE organization_permission FROM sgis;
GRANT ALL ON TABLE organization_permission TO sgis;
GRANT SELECT ON TABLE organization_permission TO sgis_readonly;


--
-- Name: organization_permission_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE organization_permission_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE organization_permission_id_seq FROM sgis;
GRANT ALL ON SEQUENCE organization_permission_id_seq TO sgis;
GRANT SELECT ON SEQUENCE organization_permission_id_seq TO sgis_readonly;


--
-- Name: south_migrationhistory; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE south_migrationhistory FROM PUBLIC;
REVOKE ALL ON TABLE south_migrationhistory FROM sgis;
GRANT ALL ON TABLE south_migrationhistory TO sgis;
GRANT SELECT ON TABLE south_migrationhistory TO sgis_readonly;


--
-- Name: south_migrationhistory_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE south_migrationhistory_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE south_migrationhistory_id_seq FROM sgis;
GRANT ALL ON SEQUENCE south_migrationhistory_id_seq TO sgis;
GRANT SELECT ON SEQUENCE south_migrationhistory_id_seq TO sgis_readonly;


--
-- Name: thumbnail_kvstore; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE thumbnail_kvstore FROM PUBLIC;
REVOKE ALL ON TABLE thumbnail_kvstore FROM sgis;
GRANT ALL ON TABLE thumbnail_kvstore TO sgis;
GRANT SELECT ON TABLE thumbnail_kvstore TO sgis_readonly;


--
-- Name: tree_incident; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE tree_incident FROM PUBLIC;
REVOKE ALL ON TABLE tree_incident FROM sgis;
GRANT ALL ON TABLE tree_incident TO sgis;
GRANT SELECT ON TABLE tree_incident TO sgis_readonly;


--
-- Name: tree_attack; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE tree_attack FROM PUBLIC;
REVOKE ALL ON TABLE tree_attack FROM sgis;
GRANT ALL ON TABLE tree_attack TO sgis;
GRANT SELECT ON TABLE tree_attack TO sgis_readonly;


--
-- Name: wiki_article; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_article FROM PUBLIC;
REVOKE ALL ON TABLE wiki_article FROM sgis;
GRANT ALL ON TABLE wiki_article TO sgis;
GRANT SELECT ON TABLE wiki_article TO sgis_readonly;


--
-- Name: wiki_article_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE wiki_article_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE wiki_article_id_seq FROM sgis;
GRANT ALL ON SEQUENCE wiki_article_id_seq TO sgis;
GRANT SELECT ON SEQUENCE wiki_article_id_seq TO sgis_readonly;


--
-- Name: wiki_articleforobject; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_articleforobject FROM PUBLIC;
REVOKE ALL ON TABLE wiki_articleforobject FROM sgis;
GRANT ALL ON TABLE wiki_articleforobject TO sgis;
GRANT SELECT ON TABLE wiki_articleforobject TO sgis_readonly;


--
-- Name: wiki_articleforobject_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE wiki_articleforobject_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE wiki_articleforobject_id_seq FROM sgis;
GRANT ALL ON SEQUENCE wiki_articleforobject_id_seq TO sgis;
GRANT SELECT ON SEQUENCE wiki_articleforobject_id_seq TO sgis_readonly;


--
-- Name: wiki_articleplugin; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_articleplugin FROM PUBLIC;
REVOKE ALL ON TABLE wiki_articleplugin FROM sgis;
GRANT ALL ON TABLE wiki_articleplugin TO sgis;
GRANT SELECT ON TABLE wiki_articleplugin TO sgis_readonly;


--
-- Name: wiki_articleplugin_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE wiki_articleplugin_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE wiki_articleplugin_id_seq FROM sgis;
GRANT ALL ON SEQUENCE wiki_articleplugin_id_seq TO sgis;
GRANT SELECT ON SEQUENCE wiki_articleplugin_id_seq TO sgis_readonly;


--
-- Name: wiki_articlerevision; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_articlerevision FROM PUBLIC;
REVOKE ALL ON TABLE wiki_articlerevision FROM sgis;
GRANT ALL ON TABLE wiki_articlerevision TO sgis;
GRANT SELECT ON TABLE wiki_articlerevision TO sgis_readonly;


--
-- Name: wiki_articlerevision_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE wiki_articlerevision_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE wiki_articlerevision_id_seq FROM sgis;
GRANT ALL ON SEQUENCE wiki_articlerevision_id_seq TO sgis;
GRANT SELECT ON SEQUENCE wiki_articlerevision_id_seq TO sgis_readonly;


--
-- Name: wiki_articlesubscription; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_articlesubscription FROM PUBLIC;
REVOKE ALL ON TABLE wiki_articlesubscription FROM sgis;
GRANT ALL ON TABLE wiki_articlesubscription TO sgis;
GRANT SELECT ON TABLE wiki_articlesubscription TO sgis_readonly;


--
-- Name: wiki_attachment; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_attachment FROM PUBLIC;
REVOKE ALL ON TABLE wiki_attachment FROM sgis;
GRANT ALL ON TABLE wiki_attachment TO sgis;
GRANT SELECT ON TABLE wiki_attachment TO sgis_readonly;


--
-- Name: wiki_attachmentrevision; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_attachmentrevision FROM PUBLIC;
REVOKE ALL ON TABLE wiki_attachmentrevision FROM sgis;
GRANT ALL ON TABLE wiki_attachmentrevision TO sgis;
GRANT SELECT ON TABLE wiki_attachmentrevision TO sgis_readonly;


--
-- Name: wiki_attachmentrevision_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE wiki_attachmentrevision_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE wiki_attachmentrevision_id_seq FROM sgis;
GRANT ALL ON SEQUENCE wiki_attachmentrevision_id_seq TO sgis;
GRANT SELECT ON SEQUENCE wiki_attachmentrevision_id_seq TO sgis_readonly;


--
-- Name: wiki_image; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_image FROM PUBLIC;
REVOKE ALL ON TABLE wiki_image FROM sgis;
GRANT ALL ON TABLE wiki_image TO sgis;
GRANT SELECT ON TABLE wiki_image TO sgis_readonly;


--
-- Name: wiki_imagerevision; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_imagerevision FROM PUBLIC;
REVOKE ALL ON TABLE wiki_imagerevision FROM sgis;
GRANT ALL ON TABLE wiki_imagerevision TO sgis;
GRANT SELECT ON TABLE wiki_imagerevision TO sgis_readonly;


--
-- Name: wiki_reusableplugin; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_reusableplugin FROM PUBLIC;
REVOKE ALL ON TABLE wiki_reusableplugin FROM sgis;
GRANT ALL ON TABLE wiki_reusableplugin TO sgis;
GRANT SELECT ON TABLE wiki_reusableplugin TO sgis_readonly;


--
-- Name: wiki_reusableplugin_articles; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_reusableplugin_articles FROM PUBLIC;
REVOKE ALL ON TABLE wiki_reusableplugin_articles FROM sgis;
GRANT ALL ON TABLE wiki_reusableplugin_articles TO sgis;
GRANT SELECT ON TABLE wiki_reusableplugin_articles TO sgis_readonly;


--
-- Name: wiki_reusableplugin_articles_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE wiki_reusableplugin_articles_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE wiki_reusableplugin_articles_id_seq FROM sgis;
GRANT ALL ON SEQUENCE wiki_reusableplugin_articles_id_seq TO sgis;
GRANT SELECT ON SEQUENCE wiki_reusableplugin_articles_id_seq TO sgis_readonly;


--
-- Name: wiki_revisionplugin; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_revisionplugin FROM PUBLIC;
REVOKE ALL ON TABLE wiki_revisionplugin FROM sgis;
GRANT ALL ON TABLE wiki_revisionplugin TO sgis;
GRANT SELECT ON TABLE wiki_revisionplugin TO sgis_readonly;


--
-- Name: wiki_revisionpluginrevision; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_revisionpluginrevision FROM PUBLIC;
REVOKE ALL ON TABLE wiki_revisionpluginrevision FROM sgis;
GRANT ALL ON TABLE wiki_revisionpluginrevision TO sgis;
GRANT SELECT ON TABLE wiki_revisionpluginrevision TO sgis_readonly;


--
-- Name: wiki_revisionpluginrevision_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE wiki_revisionpluginrevision_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE wiki_revisionpluginrevision_id_seq FROM sgis;
GRANT ALL ON SEQUENCE wiki_revisionpluginrevision_id_seq TO sgis;
GRANT SELECT ON SEQUENCE wiki_revisionpluginrevision_id_seq TO sgis_readonly;


--
-- Name: wiki_simpleplugin; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_simpleplugin FROM PUBLIC;
REVOKE ALL ON TABLE wiki_simpleplugin FROM sgis;
GRANT ALL ON TABLE wiki_simpleplugin TO sgis;
GRANT SELECT ON TABLE wiki_simpleplugin TO sgis_readonly;


--
-- Name: wiki_urlpath; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON TABLE wiki_urlpath FROM PUBLIC;
REVOKE ALL ON TABLE wiki_urlpath FROM sgis;
GRANT ALL ON TABLE wiki_urlpath TO sgis;
GRANT SELECT ON TABLE wiki_urlpath TO sgis_readonly;


--
-- Name: wiki_urlpath_id_seq; Type: ACL; Schema: public; Owner: sgis
--

REVOKE ALL ON SEQUENCE wiki_urlpath_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE wiki_urlpath_id_seq FROM sgis;
GRANT ALL ON SEQUENCE wiki_urlpath_id_seq TO sgis;
GRANT SELECT ON SEQUENCE wiki_urlpath_id_seq TO sgis_readonly;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: public; Owner: postgres
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES  FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES  FROM postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON TABLES  TO sgis_readonly;


--
-- PostgreSQL database dump complete
--
