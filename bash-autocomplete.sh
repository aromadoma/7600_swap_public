_CONFIG_GENERATOR_COMPLETE=bash_source config-generator > ~/.bash_config_generator_autocomplete.sh
if grep -q ~/.bash_config_generator_autocomplete.sh ~/.bashrc
then
	echo "Автозаполнение для config-generator уже включено в bash"
else
	echo . ~/.bash_config_generator_autocomplete.sh >> ~/.bashrc
fi
