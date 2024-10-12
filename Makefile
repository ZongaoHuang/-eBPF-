.PHONY: install coverage test docs help generate_tools
.DEFAULT_GOAL := help

define BROWSER_PYSCRIPT
import os, webbrowser, sys

try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"
INSTALL_LOCATION := ~/.local

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

generate-tools: ## generate libbpf tools and headers
	make -C bpftools

install-deps: ## install deps
	sudo apt update
	sudo apt-get install libcurl4-openssl-dev libelf-dev clang llvm ## libgtest-dev
	mkdir -p third_party/prometheus-cpp/_build
	cd third_party/prometheus-cpp/_build && sudo cmake .. -DBUILD_SHARED_LIBS=ON -DENABLE_PUSH=OFF -DENABLE_COMPRESSION=OFF
	cd third_party/prometheus-cpp/_build && sudo cmake --build . --parallel 4
	cd third_party/prometheus-cpp/_build && sudo cmake --install .

test: generate-tools ## run tests quickly with ctest
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Dagent_ENABLE_UNIT_TESTING=1 -DCMAKE_BUILD_TYPE="Release"
	cmake --build build --config Release
	cd build/ && ctest -C Release -VV

coverage: generate-tools ## check code coverage quickly GCC
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Dagent_ENABLE_CODE_COVERAGE=1
	cmake --build build --config Release
	cd build/ && ctest -C Release -VV
	cd .. && (bash -c "find . -type f -name '*.gcno' -exec gcov -pb {} +" || true)

docs: generate-tools ## generate Doxygen HTML documentation, including API docs
	rm -rf docs/
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Dagent_ENABLE_DOXYGEN=1 -Dagent_ENABLE_UNIT_TESTING=0 -Dagent_USE_GTEST=0 -DCMAKE_BUILD_TYPE=Release
	cmake --build build --target doxygen-docs
	mkdir docs/html/doc/
	cp -r doc/imgs docs/html/
	cp -r doc/imgs docs/html/doc/
	$(BROWSER) docs/html/index.html

install: generate-tools ## install the package to the `INSTALL_LOCATION`
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -DCMAKE_BUILD_TYPE=Release
	cmake --build build --config Release
	cmake --build build --target install --config Release

format: ## format the project sources
	cmake -Bbuild
	cmake --build build --target clang-format

clean: ## clean the project build files
	rm -rf build/
	rm -rf docs/
	rm -rf third_party/prometheus-cpp/_build/
	make -C bpftools clean
