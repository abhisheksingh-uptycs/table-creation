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
  cout<<" 1 "<<path<<" 2 ";
  unordered_map<string, string> packages;
  string line, version, name;
  string packageName, packageVersion, first, second;

  ifstream vulnerableFile(
      path);
  if (vulnerableFile.is_open()) {
    while (vulnerableFile) {
      getline(vulnerableFile, line);
      istringstream iss(line);
      iss >> name >> version;
      packages[name] = version;
    }
  }
  vulnerableFile.close();
  ifstream packagesFile("/var/lib/dpkg/status");
  if (packagesFile.is_open()) {
    while (packagesFile) {
      getline(packagesFile, line);
      if (!line.empty()) {
        istringstream iss(line);
        iss >> first >> second;
        if (first == "Package:") {
          packageName = second;
        } else if (first == "Version:") {
          packageVersion = second;
        }
      } else {
        if (packages[packageName] == packageVersion) {
          Row r;
          r["package_name"] = packageName;
          r["package_version"] = packageVersion;
          r["path"] = path;
          rows.push_back(std::move(r));
        }
      }
    }
    packagesFile.close();
  }
  cout<<"done";
  return rows;
}
} // namespace tables
} // namespace osquery
