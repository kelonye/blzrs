test:
	@make -C bluzelle --no-print-directory

example:
	@make -C example --no-print-directory

uat:
	@make -C uat --no-print-directory

publish:
	@make publish -C bluzelle --no-print-directory

.PHONY: test \
	example \
	uat \
	publish
	