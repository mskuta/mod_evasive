MODNAME := evasive20
LIBNAME := mod_$(MODNAME)

$(LIBNAME).la: $(LIBNAME).c
	apxs -c $<

.PHONY: clean
clean:
	-rm -f -r .libs
	-rm -f $(LIBNAME).la
	-rm -f $(LIBNAME).lo
	-rm -f $(LIBNAME).slo

.PHONY: install
install: $(LIBNAME).la
	apxs -n $(MODNAME) -i -a $<
	strip $(shell . ./$< && echo \'$$libdir/$$dlname\')

.PHONY: pretty
pretty: $(LIBNAME).c
	clang-format -i $<

