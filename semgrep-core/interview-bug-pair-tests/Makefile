# TESTS FOR INTERVIEWING

all:
		cd .. && make

test:
		../_build/default/src/cli/Main.exe -config basic_new.yaml basic.py -lang python
		../_build/default/src/cli/Main.exe -config basic_old.yaml basic.py -lang python
		@echo "\n**********************\n"
		../_build/default/src/cli/Main.exe -config edge_case_new.yaml edge_case.py -lang python
		../_build/default/src/cli/Main.exe -config edge_case_old.yaml edge_case.py -lang python
