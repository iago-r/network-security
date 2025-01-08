def find_urls_login(list_of_strings, lista_of_words):
    """

    List to store the strings that contain any of the words
    Iterate over each string in the list of strings
    Iterate over each word in the list of words
    Check if the word is present in the string
    Add the string to the list of results and exit the inner loop

    """
    found_urls = []

    for string in list_of_strings:
        for word in lista_of_words:
            if word in string:
                found_urls.append(string)
                break
    return found_urls
