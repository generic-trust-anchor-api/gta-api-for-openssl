
# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

# Global project definition for OpenSSL provider implementation
project('GTA API for OpenSSL',
        ['c'],
        default_options : [
            'c_std=gnu99',
            'warning_level=3',
            'buildtype=plain',
        ],
        license: 'Apache-2.0',
        meson_version: '>=0.57.0',
        version: '0.1'
)

# Import helper functionalities
c_compiler = meson.get_compiler('c')
py = find_program('python3')
openssl_cli = find_program('openssl', required: true)

# Define project path options from the configuration file (meson_options.txt)
# Expected value of openssl_modules_dir is an absolute path when used as override.
openssl_modules_dir_override = get_option('openssl_modules_dir').strip()
if openssl_modules_dir_override != ''
   openssl_modules_dir = openssl_modules_dir_override
else
   openssl_modules_dir_result = run_command(openssl_cli, 'version', '-m', check: false)
   if openssl_modules_dir_result.returncode() != 0
      error('Failed to detect the OpenSSL provider directory. Set -Dopenssl_modules_dir=/path/to/ossl-modules to override.')
   endif

   parse_modules_dir = '''import sys
line = sys.argv[1].strip()
prefix = 'MODULESDIR:'
if not line.startswith(prefix):
    raise SystemExit(1)
modules_dir = line[len(prefix):].strip().strip('"')
if not modules_dir.startswith('/'):
    raise SystemExit(1)
print(modules_dir)
'''
   parsed_modules_dir_result = run_command(
      py,
      '-c',
      parse_modules_dir,
      openssl_modules_dir_result.stdout(),
      check: false,
   )
   if parsed_modules_dir_result.returncode() != 0
      error('Unable to parse the OpenSSL provider directory from `openssl version -m`. Set -Dopenssl_modules_dir=/path/to/ossl-modules to override.')
   endif

   openssl_modules_dir = parsed_modules_dir_result.stdout().strip()
endif
message('OpenSSL provider install dir: ' + openssl_modules_dir)

integration_test_dir    = join_paths(meson.project_source_root(), 'tests/integration')

# Default value of gta_state_directory 
gta_state_directory     = get_option('gta_state_directory')  

# Specify global compiler options
add_project_arguments(
   c_compiler.get_supported_arguments(
        '-Wextra',
        '-Wformat-truncation=0',
        '-Wpedantic',
        '-Wno-unused-function',
        '-Wno-unused-parameter',
   ),
   language: 'c'
)

# Specify project compile options
# Specify the GTA_STATE_DIRECTORY directory macro as compiler option
GTA_STATE_DIRECTORY_c_args = [
   '-DGTA_STATE_DIRECTORY="@0@"'.format(gta_state_directory),
]
add_project_arguments(GTA_STATE_DIRECTORY_c_args, language: 'c')

# Activate PQC support
if get_option('enable-post-quantum-crypto')
   add_project_arguments('-DENABLE_PQC', language: 'c')
endif

# Logger configuration
# Log level (TRACE 0, DEBUG 1, INFO 2, WARN 3, ERROR 4)
add_project_arguments('-DLOG_LEVEL=@0@'.format(get_option('log_level').to_string()), language: 'c')

# Enable to show base64 decoded data in the log
if get_option('log_b64_on')
   add_project_arguments('-DLOG_B64_ON', language: 'c')
endif

# Enable to show byte array data in the log
if get_option('log_byte_array_on')
   add_project_arguments('-DLOG_BYTE_ARRAY_ON', language: 'c')
endif

# Enable to show state of the for cycle in the log
if get_option('log_for_cycle_on')
   add_project_arguments('-DLOG_FOR_CYCLE_ON', language: 'c')
endif

# Select build type [release | debug]
build_type = get_option('build_type')

if build_type == 'release'
   add_project_arguments(
      c_compiler.get_supported_arguments(
         '-O2',
      ),
      language: 'c'
   )
elif build_type == 'debug'
   add_project_arguments(
      c_compiler.get_supported_arguments(
         '-O0',
         '-g',
      ),
      language: 'c'
   )
endif

# Dependencies
deps = []
# 1. OpenSSL
openssl_version_req = '>=3.0.0'
if get_option('enable-post-quantum-crypto')
   openssl_version_req = '>=3.5.0'
endif
openssl_dep = dependency('openssl', version: openssl_version_req, required: true)
deps += openssl_dep

# 2. GTA API
gta_dep = dependency('libgta', required: true)
deps += gta_dep

# 3. GTA API SW Provider (merged static lib, the file needs to be stored manually in a subfolder)
gta_lib_dir = join_paths(meson.project_source_root(), 'deps', 'gta_api', 'lib_latest')
gta_sw_provider_normalized_dep = c_compiler.find_library('gta_sw_provider_merged', dirs: [gta_lib_dir], required: true)
deps += gta_sw_provider_normalized_dep

# 4. Test dependency
bash_test_tools_project = subproject('bash_test_tools')
bash_test_tools_path = join_paths(
   meson.project_source_root(),
   'subprojects',
   'bash_test_tools',
   'bash_test_tools',
)

# Define the sources
collect_provider_sources = '''import glob
import sys

enable_pqc = sys.argv[1] == 'true'

for path in glob.glob('provider/**/*.c', recursive=True):
   if not enable_pqc and path.startswith('provider/algorithms/mldsa/'):
      continue
   print(path)
'''
res = run_command(
   py,
   '-c',
   collect_provider_sources,
   get_option('enable-post-quantum-crypto').to_string(),
   check: true,
)

if res.returncode() != 0
   error('Error occurred while collecting the source files: @0@'.format(res.stderr()))
endif

provider_src = []
out = res.stdout().strip()
if out != ''
   provider_src = out.split('\n')
endif

message('Identified source files: ' + out)

# Shared library configuration
# The output is 'gta.so' (not 'libgta.so'), because name_prefix is empty 
openssl_provider_with_gta = shared_module(
   'gta',
   provider_src,
   name_prefix: '',
   dependencies: deps,
   install: true,
   install_dir: openssl_modules_dir,
)

# Run test
run_test_suit = find_program(meson.project_source_root() + '/tests/integration/run_tests.sh')
test(
   'run_test_suit',
   run_test_suit,
   workdir : integration_test_dir,
   env: {
      'BASH_TEST_TOOLS' : bash_test_tools_path,
      'WORK_DIR' : meson.project_build_root(),
   },
   is_parallel : false,
   timeout : 0
)
