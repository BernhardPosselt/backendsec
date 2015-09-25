all:
	cleaver ./presentation.md --output ./index.html

watch:
	cleaver watch ./presentation.md --output ./index.html
