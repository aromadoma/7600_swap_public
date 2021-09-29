if grep -q CONFIG_GENERATOR_COMPLETE=source_bash ~/.bashrc
then
	echo "Автозаполнение для config-generator уже включено в bash"
else
	echo 'eval "$(_CONFIG_GENERATOR_COMPLETE=source_bash config-generator)"' >> ~/.bashrc
fi
