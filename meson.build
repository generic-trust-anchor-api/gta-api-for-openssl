
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
fs = import('fs')

# Define project path options from the configuration file (meson_options.txt)
# Expected value of openssl_modules_dir is an absolute path. 
openssl_modules_dir     = get_option('openssl_modules_dir')
client_dir              = join_paths(meson.project_source_root(), get_option('client_dir'))
server_dir              = join_paths(meson.project_source_root(), get_option('server_dir'))
ca_dir                  = join_paths(meson.project_source_root(), get_option('ca_dir'))
integration_test_dir    = join_paths(meson.project_source_root(), get_option('integration_test_dir'))

# Serialized_data_dir can be relative path or empty string (if empty, then value is client_dir/serialized_data)
serialized_opt          = get_option('serialized_data_dir')

if serialized_opt == ''
  serialized_data_dir = join_paths(client_dir, 'serialized_data')
else
  serialized_data_dir = join_paths(meson.project_source_root(), serialized_opt)
endif

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
build_type = get_option('build')

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
if dilithium_on

   # 2. Open Quantum Safe low level library (liboqs) (build dependency | static library)
   oqs_library_dep = dependency('liboqs', required: true)
   deps += oqs_library_dep

   # 3. Open Quantum Safe OpenSSL provider (oqs-provider) (runtime dependency | static library)
   oqs_provider_dep = dependency('oqs-provider', required: true)
   deps += oqs_provider_dep

endif

# 4. GTA API
gta_dep = dependency('libgta', required: true)
deps += gta_dep

# 5. GTA API SW Provider (normalized, the file needs to be stored manually in a subfolder)
gta_sw_provider_normalized_dep = cc.find_library('gta_sw_provider_merged', dirs: [gta_lib_dir], required: true)
deps += gta_sw_provider_normalized_dep

# 6. Mathematical library
dep_math = dependency('libm', required: true) 
deps += dep_math

# 7. Test dependency
bash_test_tool_url = 'https://raw.githubusercontent.com/thorsteinssonh/bash_test_tools/master/bash_test_tools'

# Define the sources
provider_src = fs.glob('provider/**/*.c')

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
   command: ['meson', 'install', '-C', meson.build_root()]
)

# Uninstall
run_target('uninstall',
  command: ['sh', '-c', 'rm -f "@0@/gta.so"'.format(openssl_modules_dir)]
)

# Remove
run_target('remove',
  command: ['sh', '-c',
    'rm -rf "@0@" && ' +
    'rm -rf "@1@" && ' +
    'rm -f "@2@"/*.pem && ' +
    'rm -f "@3@"/*.pem && ' +
    'rm -f "@4@/tools/bash_test_tools"'
      .format(ca_dir,
              join_paths(client_dir, 'serialized_data'),
              client_dir,
              server_dir,
              integration_test_dir)
  ]
)

# Prepare test tools
fetch_test_tools = run_target('fetch_test_tools',
  command: ['sh', '-c',
    'mkdir -p "@0@/tools" && ' +
    'wget -q -O "@0@/tools/bash_test_tools" "@1@" && ' +
    'chmod +x "@0@/tools/bash_test_tools"'
      .format(integration_test_dir,
       bash_test_tool_url)
  ]
)

# Run test
run_target('test',
  command: ['sh', '-c', 'cd "@0@" && ./run_tests.sh'.format(integration_test_dir)],
  depends: [fetch_test_tools]
)
