CC=pdflatex
BIB=bibtex
NAME=main

all:
	$(CC) $(NAME).tex

release:
	$(CC) $(NAME).tex
	$(BIB) $(NAME)
	$(CC) $(NAME).tex
	$(CC) $(NAME).tex

clean:
	@rm -fv *.aux *.bbl *.blg *.pdf *.xml *.fls *.log *.out *.fdb_latexmk comment.cut
