# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/uECQV/uECQV_standalone

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/uECQV/uECQV_standalone/build

# Include any dependencies generated for this target.
include CMakeFiles/BEKMP.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/BEKMP.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/BEKMP.dir/flags.make

CMakeFiles/BEKMP.dir/main.c.o: CMakeFiles/BEKMP.dir/flags.make
CMakeFiles/BEKMP.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/uECQV/uECQV_standalone/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/BEKMP.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/BEKMP.dir/main.c.o   -c /root/uECQV/uECQV_standalone/main.c

CMakeFiles/BEKMP.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/BEKMP.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/uECQV/uECQV_standalone/main.c > CMakeFiles/BEKMP.dir/main.c.i

CMakeFiles/BEKMP.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/BEKMP.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/uECQV/uECQV_standalone/main.c -o CMakeFiles/BEKMP.dir/main.c.s

CMakeFiles/BEKMP.dir/BEKMP.c.o: CMakeFiles/BEKMP.dir/flags.make
CMakeFiles/BEKMP.dir/BEKMP.c.o: ../BEKMP.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/uECQV/uECQV_standalone/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/BEKMP.dir/BEKMP.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/BEKMP.dir/BEKMP.c.o   -c /root/uECQV/uECQV_standalone/BEKMP.c

CMakeFiles/BEKMP.dir/BEKMP.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/BEKMP.dir/BEKMP.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/uECQV/uECQV_standalone/BEKMP.c > CMakeFiles/BEKMP.dir/BEKMP.c.i

CMakeFiles/BEKMP.dir/BEKMP.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/BEKMP.dir/BEKMP.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/uECQV/uECQV_standalone/BEKMP.c -o CMakeFiles/BEKMP.dir/BEKMP.c.s

CMakeFiles/BEKMP.dir/sha.c.o: CMakeFiles/BEKMP.dir/flags.make
CMakeFiles/BEKMP.dir/sha.c.o: ../sha.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/uECQV/uECQV_standalone/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/BEKMP.dir/sha.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/BEKMP.dir/sha.c.o   -c /root/uECQV/uECQV_standalone/sha.c

CMakeFiles/BEKMP.dir/sha.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/BEKMP.dir/sha.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/uECQV/uECQV_standalone/sha.c > CMakeFiles/BEKMP.dir/sha.c.i

CMakeFiles/BEKMP.dir/sha.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/BEKMP.dir/sha.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/uECQV/uECQV_standalone/sha.c -o CMakeFiles/BEKMP.dir/sha.c.s

CMakeFiles/BEKMP.dir/local_sha2.c.o: CMakeFiles/BEKMP.dir/flags.make
CMakeFiles/BEKMP.dir/local_sha2.c.o: ../local_sha2.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/uECQV/uECQV_standalone/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/BEKMP.dir/local_sha2.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/BEKMP.dir/local_sha2.c.o   -c /root/uECQV/uECQV_standalone/local_sha2.c

CMakeFiles/BEKMP.dir/local_sha2.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/BEKMP.dir/local_sha2.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/uECQV/uECQV_standalone/local_sha2.c > CMakeFiles/BEKMP.dir/local_sha2.c.i

CMakeFiles/BEKMP.dir/local_sha2.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/BEKMP.dir/local_sha2.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/uECQV/uECQV_standalone/local_sha2.c -o CMakeFiles/BEKMP.dir/local_sha2.c.s

# Object files for target BEKMP
BEKMP_OBJECTS = \
"CMakeFiles/BEKMP.dir/main.c.o" \
"CMakeFiles/BEKMP.dir/BEKMP.c.o" \
"CMakeFiles/BEKMP.dir/sha.c.o" \
"CMakeFiles/BEKMP.dir/local_sha2.c.o"

# External object files for target BEKMP
BEKMP_EXTERNAL_OBJECTS =

BEKMP: CMakeFiles/BEKMP.dir/main.c.o
BEKMP: CMakeFiles/BEKMP.dir/BEKMP.c.o
BEKMP: CMakeFiles/BEKMP.dir/sha.c.o
BEKMP: CMakeFiles/BEKMP.dir/local_sha2.c.o
BEKMP: CMakeFiles/BEKMP.dir/build.make
BEKMP: /usr/lib/x86_64-linux-gnu/libcurl.so
BEKMP: CMakeFiles/BEKMP.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/uECQV/uECQV_standalone/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable BEKMP"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/BEKMP.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/BEKMP.dir/build: BEKMP

.PHONY : CMakeFiles/BEKMP.dir/build

CMakeFiles/BEKMP.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/BEKMP.dir/cmake_clean.cmake
.PHONY : CMakeFiles/BEKMP.dir/clean

CMakeFiles/BEKMP.dir/depend:
	cd /root/uECQV/uECQV_standalone/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/uECQV/uECQV_standalone /root/uECQV/uECQV_standalone /root/uECQV/uECQV_standalone/build /root/uECQV/uECQV_standalone/build /root/uECQV/uECQV_standalone/build/CMakeFiles/BEKMP.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/BEKMP.dir/depend
