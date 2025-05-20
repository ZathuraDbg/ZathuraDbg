HEADER_ARG = -I../
ICICLE_ARGS_DEBUG = -L../src/target/debug -l:libicicle.a -lkeystone
ICICLE_ARGS_RELEASE = -L../src/target/release -l:libicicle.a
CC_ARGS = -lm
OS := $(shell uname 2>/dev/null || echo Windows)

ifeq ($(OS), Windows)
    RM = del /F /Q
else
    RM = rm -f
endif

tests:
	g++ mapping_test.cpp $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o mapping-test-debug
	cc tests.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o tests-debug
	cc serialization_test.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o serialization-test-debug
	cc compression_test.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o compression-test-debug
	cc debug_features.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o features-debug
	cc hook_tests.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o hook-tests-debug
	cc snapshot_tests.c $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o snapshot-tests-debug
# 	g++ archs.cpp $(HEADER_ARG) $(ICICLE_ARGS_DEBUG) $(CC_ARGS) -o archs-tests-debug

tests-release:
	cc tests.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o tests-release
	cc serialization_test.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o serialization-test-release
	cc compression_test.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o compression-test-release
	cc hook_tests.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o hook-tests-release
	cc snapshot_tests.c $(HEADER_ARG) $(ICICLE_ARGS_RELEASE) $(CC_ARGS) -o snapshot-tests-release

all: tests tests-release

run: tests
	./tests-debug
	./serialization-test-debug
	./compression-test-debug
	./hook-tests-debug
	./snapshot-tests-debug

run-serialization: tests
	./serialization-test-debug

run-compression: tests
	./compression-test-debug

run-release: tests-release
	./tests-release
	./serialization-test-release
	./compression-test-release
	./hook-tests-release
	./snapshot-tests-release

run-all: tests tests-release
	./tests-debug
	./serialization-test-debug
	./compression-test-debug
	./hook-tests-debug
	./snapshot-tests-debug
	echo "Ran debug mode binary. Now running release mode binary..."
	./tests-release
	./serialization-test-release
	./compression-test-release
	./hook-tests-release
	./snapshot-tests-release
	echo "Executed both."

clean:
	$(RM) ./tests-debug
	$(RM) ./mapping-test-debug
	$(RM) ./serialization-test-debug
	$(RM) ./compression-test-debug
	$(RM) ./hook-tests-debug
	$(RM) ./snapshot-tests-debug
	$(RM) ./features-debug
	$(RM) ./tests-release
	$(RM) ./serialization-test-release
	$(RM) ./compression-test-release
	$(RM) ./hook-tests-release
	$(RM) ./snapshot-tests-release
	$(RM) ./mapping-test-release
	$(RM) *.bin 