CC ?= gcc
CXX ?= g++

CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -Iinclude
CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -Werror -Iinclude

BIN_DIR := bin
TARGETS := $(BIN_DIR)/souei $(BIN_DIR)/chronoa $(BIN_DIR)/ranga $(BIN_DIR)/libranga.so

.PHONY: all clean test

all: $(TARGETS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/souei: src/souei.cpp include/tempest_contract.h | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ src/souei.cpp

$(BIN_DIR)/chronoa: src/chronoa.cpp include/tempest_contract.h | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ src/chronoa.cpp

$(BIN_DIR)/ranga: src/ranga.c include/tempest_contract.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ src/ranga.c

$(BIN_DIR)/libranga.so: src/libranga.c include/tempest_contract.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ src/libranga.c

test: all
	python3 tests/test_tempest.py

clean:
	rm -rf $(BIN_DIR)
