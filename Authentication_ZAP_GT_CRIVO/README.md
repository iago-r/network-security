# Authentication_ZAP_GT_CRIVO

## Resumo
    This initial version uses various functionalities of the tool itself, including the auto-detection method to validate authentication and session management. According to tests, auto-detection has proven to be robust and quite useful. Therefore, to simplify the execution flow, it was implemented with auto-detection.

    As tests are conducted and applications prove to be resistant to auto-detection methods, we can reimplement the regex capture configurations that have already been developed.

## Authentication
    find_element_by_attribute: Function responsible for identifying login field elements based on the elements found.
    validate: Function that checks if the form field is on the screen, validating if the authentication was successful.
    check_credentials: Verifies if the credentials were passed in the POST request.

## Base_context
    Configuration file used to generate the context.

## Keywords
    List of keywords used to find elements during execution.

## Libs
    Functions responsible for concatenating the authentication regex and returning the output folder path based on the home directory.

## Output_context
    Directory for creating the context plan. 

## Params
    Define_type_authentication: Defines the structure of the request by identifying if the authentication type is form or JSON.

## Request_Text
    replace_words: Creates the request pattern for authentication in the context.

## Urls_login
    find_urls_login: Uses keywords during the scan with the spider to return candidate login URLs.

## User_data
    User configuration files for authentication.

## Main
    Proxy configuration and webdriver configuration to ensure communication through the proxy.
    
    Main program flow capturing URLs, sending authentication requests, and defining the context plan.
    
    Some sections will be replaced by environment variables.