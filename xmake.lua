add_rules("mode.debug", "mode.release")

set_project("jljudge")
set_version("0.2.0", {build = "%Y%m%d%H%M"})

set_languages("c++17")

add_cxxflags("clang::-ftime-trace")
add_ldflags("-static-libgcc", "-static-libstdc++", {force = true})
add_ldflags("-static")

set_warnings("allextra", "pedantic")
if is_mode("release") then
  set_optimize("fastest")
end

add_requires("fmt")
add_requires("yaml-cpp")
add_requires("libxlsxwriter")
add_requires("zlib")

add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode"})
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})

target("judgecli")
  set_kind("binary")

  set_configdir("$(buildir)/generated")
  add_configfiles("src/config.h.in")
  add_includedirs("$(buildir)/generated")

  add_files("src/judge_core.cpp", "src/judge_local.cpp")
  add_links("pthread")
  add_links("rt")

  add_packages("fmt")
  add_packages("yaml-cpp")
  add_packages("libxlsxwriter")
  add_packages("zlib")
target_end()
