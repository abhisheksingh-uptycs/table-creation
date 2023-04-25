#include <fstream>
#include <iostream>
#include <osquery/core/tables.h>
#include <sstream>
#include <unordered_map>
#include</home/adhisheksingh/osquery/osquery/sql/sql.h>

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
  return rows;
}
} // namespace tables
} // namespace osquery