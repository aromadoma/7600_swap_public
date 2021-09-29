build:
	poetry build

install:
	poetry build
	python3 -m pip install --user dist/*.whl
	bash bash-autocomplete.sh

remove:
	python3 -m pip uninstall 7600-swap-tool -y
	rm dist/*

reinstall:
	python3 -m pip uninstall 7600-swap-tool -y
	rm dist/*
	poetry build
	python3 -m pip install --user dist/*.whl
	bash bash-autocomplete.sh

bash-autocomplete:
	bash bash-autocomplete.sh
