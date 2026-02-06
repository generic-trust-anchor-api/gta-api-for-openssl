
# SPDX-FileCopyrightText: Copyright 2025 Siemens
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
        meson_version: '>=0.56.0',
        version: '0.1'
)

# Import helper functionalities
c_compiler = meson.get_compiler('c')

# Define project path options from the configuration file (meson_options.txt)
# Expected value of openssl_modules_dir is an absolute path. 
openssl_modules_dir     = get_option('openssl_modules_dir')
client_dir              = join_paths(meson.project_source_root(), get_option('client_dir'))
server_dir              = join_paths(meson.project_source_root(), get_option('server_dir'))
ca_dir                  = join_paths(meson.project_source_root(), get_option('ca_dir'))
integration_test_dir    = join_paths(meson.project_source_root(), get_option('integration_test_dir'))

# Serialized_data_dir can be relative path or empty string (if empty, then value is client_dir/serialized_data)
serialized_data_dir     = get_option('serialized_data_dir')  

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
# Specify the SERIALIZATION_FOLDER directory macro as compiler option
serialization_folder_c_args = [
   '-DSERIALIZATION_FOLDER="@0@"'.format(serialized_data_dir),
]
add_project_arguments(serialization_folder_c_args, language: 'c')

# Activate elliptic curve support
if get_option('ec_on')
   add_project_arguments('-DEC_ON', language: 'c')
endif

# Activate dilithium (pqc) support
if get_option('dilithium_on')
   add_project_arguments('-DDILITHIUM_ON', language: 'c')
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
openssl_dep = dependency('openssl', required: true)
deps += openssl_dep

# Post quantum support is deactivated
dilithium_on = get_option('dilithium_on')
if dilithium_on
   # 2. Open Quantum Safe low level library (liboqs) (build dependency | static library)
   oqs_library_dep = dependency('liboqs', required: true)
   deps += oqs_library_dep

   # 3. Open Quantum Safe OpenSSL provider (oqs-provider) (runtime dependency | dyn library)
   oqs_provider_dep = dependency('oqs-provider', required: true)
   deps += oqs_provider_dep

   # 4. Mathematical library
   dep_math = dependency('libm', required: false) 
   deps += dep_math
endif

# 5. GTA API
gta_dep = dependency('libgta', required: true)
deps += gta_dep

# 6. GTA API SW Provider (normalized, the file needs to be stored manually in a subfolder)
gta_lib_dir = join_paths(meson.project_source_root(), 'deps', 'gta_api', 'lib_latest')
gta_sw_provider_normalized_dep = c_compiler.find_library('gta_sw_provider_merged', dirs: [gta_lib_dir], required: true)
deps += gta_sw_provider_normalized_dep

# 7. Test dependency
bash_test_tool_url = 'https://raw.githubusercontent.com/thorsteinssonh/bash_test_tools/master/bash_test_tools'

# Define the sources
py = find_program('python3')

code = 'import glob; [print(f) for f in glob.glob("provider/**/*.c", recursive=True)]'
res = run_command(py, '-c', code, check: true)

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

# Custom meson targets
# Install 
run_target('install-module', 
   command: ['meson', 'install', '-C', meson.project_build_root()]
)

# Uninstall
run_target('uninstall-module',
   command: ['sh', '-c', 'rm -f "@0@/gta.so"'.format(openssl_modules_dir)]
)

# Remove
run_target('remove',
   command: ['sh', '-c',
   (
      'rm -rf "@0@" && ' +
      'rm -rf "@1@" && ' +
      'rm -f "@2@"/*.pem && ' +
      'rm -f "@3@"/*.pem && ' +
      'rm -f "@4@/tools/bash_test_tools"'
   )
      .format(ca_dir,
              join_paths(client_dir, 'serialized_data'),
              client_dir,
              server_dir,
              integration_test_dir)
  ]
)

# Prepare test tools
fetch_test_tools = custom_target(
   'fetch_test_tools',
   output: 'bash_test_tools',
   command: [
   'sh', '-c',
   (
      'mkdir -p "@0@/tools" && ' +
      'wget -q -O "@0@/tools/bash_test_tools" "@1@" && ' +
      'chmod +x "@0@/tools/bash_test_tools"'
   )
      .format(integration_test_dir, 
              bash_test_tool_url)
  ]
)

# Run test
run_target('run-test',
   command: ['sh', '-c', 'cd "@0@" && ./run_tests.sh'.format(integration_test_dir)],
   depends: [fetch_test_tools]
)

# Meson popular commands:
# 1) Create build folder and setup project:
# meson setup build -Dopenssl_modules_dir=/lib/x86_64-linux-gnu/ossl-modules -Dec_on=true -Ddilithium_on=false -Dlog_level=0 -Dlog_b64_on=true

# 2) Build project:
# meson compile -C build
# or
# ninja -C build

# 3) Install provider (gta.so copy to OPENSSL_MODULES_DIR):
# sudo meson compile -C build install-module
# or
# sudo ninja -C build install-module

# 4) Run tests
# meson compile -C build run-test
# or
# ninja -C build run-test

# 5) Remove provider (delete gta.so from OPENSSL_MODULES_DIR):
# meson compile -C build uninstall-module

# 6) Clean up test and demo project:
# meson compile -C build remove

# Clean build directory:
# meson setup --wipe build
