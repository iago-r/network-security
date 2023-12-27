from pysnmp.hlapi import *

def snmpwalk(host, community, oid, output):
    with open(output, 'w') as file:    
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((host, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            ):
                if errorIndication:
                    file.write(f"{errorIndication}")
                elif errorStatus:
                    file.write(
                        "%s at %s"
                        % (
                            errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                        )
                    )
                else:
                    # read informations in file
                    for varBind in varBinds:
                        file.write(" = ".join([x.prettyPrint() for x in varBind]) + '\n')
        except:
            print('')
            
    file.close()