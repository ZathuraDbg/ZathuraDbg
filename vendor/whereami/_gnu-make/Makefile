.PHONY: build clean

# directories
ifeq ($(realpath .),)
  $(error your version of Make doesn't support $$(realpath names...) - please use GNU Make 3.81 or later)
endif

ifeq ($(platform),)
  __uname_s := $(shell sh -c 'uname -s 2>/dev/null | tr [A-Z] [a-z] || echo unknown-platform')
  __uname_m := $(shell sh -c 'uname -m 2>/dev/null | tr [A-Z] [a-z] || echo unknown-architecture')

  ifeq ($(__uname_s),linux)
    override platform := linux
    override architecture := $(__uname_m)
  endif
  ifeq ($(__uname_s),darwin)
    override platform := mac
    override architecture := $(__uname_m)
  endif
  ifeq ($(findstring mingw,$(__uname_s)),mingw)
    override platform := windows
    override architecture := $(if $(findstring MINGW32,$(MSYSTEM)),i686,$(if $(findstring MINGW64,$(MSYSTEM)),x86_64,))
    ifeq ($(CC),cc)
      override CC := gcc
    endif
  endif
  ifeq ($(__uname_s),freebsd)
    override platform := freebsd
    override architecture := $(__uname_m)
  endif
  ifeq ($(__uname_s),openbsd)
    override platform := openbsd
    override architecture := $(__uname_m)
  endif
  ifeq ($(findstring cygwin,$(__uname_s)),cygwin)
    override platform := cygwin
    override architecture := $(__uname_m)
  endif
endif
ifeq ($(architecture),)
  override architecture := unknown-architecture
endif

prefix := $(realpath ..)
srcdir := $(realpath ../src)
exampledir := $(realpath ../example)
testdir := $(realpath ../test)
buildir := $(realpath .)/build
binsubdir := $(platform)-$(architecture)
bindir := $(prefix)/bin/$(binsubdir)

override CFLAGS += -O2 -g -Wall -pedantic -Werror -Wshadow -std=c99
override CXXFLAGS += -O2 -g -Wall -pedantic -Werror -Wshadow

ifeq ($(shell printf "int main(int argc, char* argv[]) { return 0; }\n" | $(CC) -x c -o /dev/null -Wbad-function-cast -Werror - 2> /dev/null && echo 'ok'),ok)
  override CFLAGS += -Wbad-function-cast
endif

ifeq ($(shell printf "int main(int argc, char* argv[]) { return 0; }\n" | $(CXX) -x c++ -o /dev/null -Wuseless-cast -Werror - 2> /dev/null && echo 'ok'),ok)
  override CXXFLAGS += -Wuseless-cast
endif

ifeq ($(platform),linux)
override LDFLAGS += -ldl
override CFLAGS += -fpic
override CXXFLAGS += -fpic
endif
ifeq ($(platform),freebsd)
override CFLAGS += -fpic
override CXXFLAGS += -fpic
endif
ifeq ($(platform),cygwin)
override LDFLAGS += -ldl
override CFLAGS += -fpic
override CXXFLAGS += -fpic
endif
ifeq ($(platform),android)
override CFLAGS += -fpie -pie
override CXXFLAGS += -fpie -pie
endif

ifeq ($(platform),mac)
libsuffix := .dylib
endif
ifeq ($(platform),linux)
libsuffix := .so
endif
ifeq ($(platform),windows)
libsuffix := .dll
endif
ifeq ($(platform),freebsd)
libsuffix := .so
endif
ifeq ($(platform),cygwin)
libsuffix := .dll
endif
ifeq ($(platform),android)
libsuffix := .so
endif
ifeq ($(platform),linux)
libsuffix := .so
endif

.PHONY: build-executable
build: build-executable
build-executable: $(bindir)/executable $(bindir)/executable-cpp

$(bindir)/executable: $(srcdir)/whereami.c $(srcdir)/whereami.h $(exampledir)/executable.c
	mkdir -p $(@D)
	$(CC) -I $(srcdir) $(CPPFLAGS) $(CFLAGS) $(filter-out %.h,$^) $(LDFLAGS) -o $@
	$(if $(postbuild),$(postbuild) $@)

$(bindir)/executable-cpp: $(srcdir)/whereami.c $(srcdir)/whereami.h $(exampledir)/executable.c
	mkdir -p $(@D)
	$(CXX) -x c++ -I $(srcdir) $(CPPFLAGS) $(CXXFLAGS) $(filter-out %.h,$^) $(LDFLAGS) -o $@
	$(if $(postbuild),$(postbuild) $@)

.PHONY: build-library
build: build-library
build-library: $(bindir)/library$(libsuffix) $(bindir)/library-cpp$(libsuffix)

$(bindir)/library$(libsuffix): $(srcdir)/whereami.c $(srcdir)/whereami.h $(exampledir)/library.c
	mkdir -p $(@D)
	$(CC) -I $(srcdir) $(CPPFLAGS) $(CFLAGS) $(filter-out %.h,$^) $(LDFLAGS) -shared -o $@
	$(if $(postbuild),$(postbuild) $@)

$(bindir)/library-cpp$(libsuffix): $(srcdir)/whereami.c $(srcdir)/whereami.h $(exampledir)/library.c
	mkdir -p $(@D)
	$(CXX) -x c++ -I $(srcdir) $(CPPFLAGS) $(CXXFLAGS) $(filter-out %.h,$^) $(LDFLAGS) -shared -o $@
	$(if $(postbuild),$(postbuild) $@)

clean:
	rm -rf $(buildir)
	rm -rf $(bindir)
