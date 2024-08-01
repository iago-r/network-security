#!/bin/bash

pdftk A=FirstPage.pdf B=../main.pdf C=LastPage.pdf cat A B C output Combined.pdf
