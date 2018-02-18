#include <stdio.h>

#include "tag_file.h"
#include "metadata_memory_map.h"
#include "metadata_cache.h"
#include "metadata_factory.h"
#include "validator_exception.h"

metadata_cache_t md_cache;
metadata_factory_t *md_factory;

extern void init_metadata_renderer(metadata_factory_t *md_factory);

void init(const char *policy_dir) {
  try {
    md_factory = new metadata_factory_t(policy_dir);
    init_metadata_renderer(md_factory);
  } catch (validator::exception_t &e) {
    printf("exception: %s\n", e.what().c_str());
  }
}

bool apply_tag(metadata_memory_map_t *map, address_t start, address_t end, const char *tag_name) {
  metadata_t const *md = md_factory->lookup_metadata(tag_name);
  if (!md)
    return false;
  map->add_range(start, end, md);
  return true;
}

#include <fstream>
#include <sstream>
#include <string>
bool load_range_file(metadata_memory_map_t *map, std::string file_name) {
  int lineno = 1;
  bool res = true;
  try {
    std::ifstream infile(file_name);
    std::string line;
    while (std::getline(infile, line)) {
      std::istringstream iss(line);
//      printf("Line = '%s'\n", line.c_str());
      std::vector<std::string> tokens {std::istream_iterator<std::string>{iss},
	  std::istream_iterator<std::string>{}};
      if (tokens.size() != 3) {
	fprintf(stderr, "%s: %d: bad format - wrong number of items\n", file_name.c_str(), lineno);
	res = false;
      } else {
	address_t start;
	address_t end;
	start = strtol(tokens[0].c_str(), 0, 16);
	end = strtol(tokens[1].c_str(), 0, 16);
//	printf("applying tag to 0x%x, 0x%x ... ", start, end);
	if (!apply_tag(map, start, end, tokens[2].c_str())) {
	  fprintf(stderr, "%s: %d: could not find tag %s\n", file_name.c_str(), lineno, tokens[2].c_str());
	  res = false;
	} else {
//	  printf("done\n");
	}
      }
      lineno++;
    }
  } catch (...) {
    fprintf(stderr, "error loading %s\n", file_name.c_str());
    return false;
  }
  return res;
}

void usage() {
  printf("usage: tag_range <base_address> <range_file> <tag_file>\n");
}

int main(int argc, char **argv) {
  const char *policy_dir;
  address_t base_address;
  const char *range_file_name;
  const char *file_name;

  if (argc != 5) {
    usage();
    return 0;
  }

  policy_dir = argv[1];
  base_address = strtol(argv[2], 0, 16);
  range_file_name = argv[3];
  file_name = argv[4];

  init(policy_dir);

  metadata_memory_map_t map(base_address, &md_cache);

  if (!load_range_file(&map, range_file_name))
    return 1;

  if (!save_tags(&map, file_name)) {
    printf("failed write of tag file\n");
    return 1;
  }

  return 0;
}