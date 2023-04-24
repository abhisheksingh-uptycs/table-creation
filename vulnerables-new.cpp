#include </home/adhisheksingh/osquery/build/ns_osquery_utils_linux/osquery/utils/linux/idpkgquery.h>
#include</home/adhisheksingh/osquery/osquery/sql/sql.h>
#include <fstream>
#include <iostream>
#include <osquery/core/tables.h>
#include <sstream>
#include <unordered_map>

using namespace std;

namespace osquery {
namespace tables {

QueryData genVulnerablePackages(QueryContext& context) {
  QueryData rows;
  auto paths = context.constraints["path"].getAll(EQUALS);
  auto it = paths.begin();
  string path = *it;
  unordered_map<string, string> packages;
  string line, version, name;
  string packageName, packageVersion, first, second;

  ifstream vulnerableFile(path);
  if (vulnerableFile.is_open()) {
    while (vulnerableFile) {
      getline(vulnerableFile, line);
      istringstream iss(line);
      iss >> name >> version;
      packages[name] = version;
    }
  }
  vulnerableFile.close();

  QueryData deb_packages = SQL::selectAllFrom("deb_packages");
  for (const auto& package : deb_packages) {
       if (packages[package.at("name")] == package.at("version")) {
          Row r;
          r["package_name"] = package.at("name");
          r["package_version"] = package.at("version");
          r["path"] = path;
          rows.push_back(r);
        }
    }
  



  // string dir = "/var/lib/dpkg";
  // auto dpkg_query_exp = IDpkgQuery::create(dir);
  //   auto dpkg_query = dpkg_query_exp.take();
  //   auto package_list_exp = dpkg_query->getPackageList();
  //   auto package_list = package_list_exp.take();

  // for (const auto& package : package_list) {
  //   if (packages[package.name] == package.version) {
  //         Row r;
  //         r["package_name"] = package.name;
  //         r["package_version"] = package.version;
  //         r["path"] = path;
  //         rows.push_back(r);
  //       }
  // }

  // ifstream packagesFile("/var/lib/dpkg/status");
  // if (packagesFile.is_open()) {
  //   while (packagesFile) {
  //     getline(packagesFile, line);
  //     if (!line.empty()) {
  //       istringstream iss(line);
  //       iss >> first >> second;
  //       if (first == "Package:") {
  //         packageName = second;
  //       } else if (first == "Version:") {
  //         packageVersion = second;
  //       }
  //     } else {
  //       if (packages[packageName] == packageVersion) {
  //         Row r;
  //         r["package_name"] = packageName;
  //         r["package_version"] = packageVersion;
  //         r["path"] = path;
  //         rows.push_back(r);
  //       }
  //     }
  //   }
  // }
  // packagesFile.close();
  return rows;
}
} // namespace tables
} // namespace osquery