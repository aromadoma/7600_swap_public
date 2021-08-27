build:
	poetry build

install:
	poetry build
	python3 -m pip install --user dist/*.whl

reinstall:
	python3 -m pip uninstall 7600-swap-tool -y
	rm dist/*
	poetry build
	python3 -m pip install --user dist/*.whl

bash-autocomplete:
	bash bash-autocomplete.sh
