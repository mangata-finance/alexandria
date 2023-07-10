.PHONY: default

# Configuration
ROOT_PROJECT = .
PROJECT_NAME = alexandria
BUILD_DIR = build

# Default target
default: test

# All relevant targets
all: build run test

# Targets

# Compile the project
build: FORCE
	$(MAKE) clean format
	@echo "Building..."
	~/.cairo/target/release/cairo-compile . > $(BUILD_DIR)/$(PROJECT_NAME).sierra

# Run the project
run:
	@echo "Running..."
	# TODO: enable when sample main is ready
	#cairo-run $(ROOT_PROJECT)

# Test the project
test:
	@echo "Testing everything..."
	$(MAKE) test-cairo
	$(MAKE) test-starknet

test-cairo: test-data_structures test-encoding test-math test-sorting test-searching

test-starknet: test-storage

test-data_structures:
	@echo "Testing data structures..."
	cairo-test $(ROOT_PROJECT) --filter alexandria_data_structures

test-encoding:
	@echo "Testing encoding..."
	cairo-test $(ROOT_PROJECT) --filter alexandria_encoding

test-linalg:
	@echo "Testing linalg"
	cairo-test $(PROJECT_NAME)/linalg

test-math:
	@echo "Testing math"
	cairo-test $(ROOT_PROJECT) --filter alexandria_math

test-numeric:
	@echo "Testing numeric"
	cairo-test $(PROJECT_NAME)/numeric

test-storage:
	@echo "Testing storage"
	cairo-test --starknet $(PROJECT_NAME)/storage

test-sorting:
	@echo "Testing sorting..."
	cairo-test $(ROOT_PROJECT) --filter alexandria_sorting

test-searching:
	@echo "Testing searching..."
	cairo-test $(ROOT_PROJECT) --filter alexandria_searching

# Special filter tests targets

# Run tests related to the stack
test-stack:
	@echo "Testing stack..."
	cairo-test $(ROOT_PROJECT) -f stack

# Format the project
format:
	@echo "Formatting everything..."
	~/.cairo/target/release/cairo-format --recursive --print-parsing-errors $(ROOT_PROJECT)

# Check the formatting of the project
check-format:
	@echo "Checking formatting..."
	~/.cairo/target/release/cairo-format --recursive --check $(ROOT_PROJECT)

# Clean the project
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)/*
	mkdir -p $(BUILD_DIR)


# FORCE is a special target that is always out of date
# It enable to force a target to be executed
FORCE:
