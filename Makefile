BIN_DIR = bin
TARGET_LIB = $(BIN_DIR)/libsecrets_injector.so
TARGET_LIB_GLIBC = $(BIN_DIR)/libsecrets_injector_glibc.so
TARGET_LIB_MUSL = $(BIN_DIR)/libsecrets_injector_musl.so
TEST_APP = $(BIN_DIR)/test_app

.PHONY: all test clean test-unit docker-build

all: $(TARGET_LIB) $(TARGET_LIB_GLIBC) $(TARGET_LIB_MUSL) $(TEST_APP)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(TARGET_LIB) $(TARGET_LIB_GLIBC) $(TARGET_LIB_MUSL) $(TEST_APP): src/*.zig build.zig | $(BIN_DIR)
	zig build -Doptimize=ReleaseSmall
	cp zig-out/lib/libsecrets_injector.so $(TARGET_LIB)
	cp zig-out/lib/libsecrets_injector_glibc.so $(TARGET_LIB_GLIBC)
	cp zig-out/lib/libsecrets_injector_musl.so $(TARGET_LIB_MUSL)
	cp zig-out/bin/test_app $(TEST_APP)

test-unit:
	zig build test-unit

test: all test-unit
	LIB_PATH="$(TARGET_LIB)" TEST_APP="$(TEST_APP)" ./test/run_tests.sh

docker-build:
	docker build -t secrets-injector:latest .

clean:
	rm -rf $(BIN_DIR) zig-out .zig-cache
