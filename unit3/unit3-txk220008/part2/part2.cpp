#include <iostream>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

using namespace ELFIO;

std::vector<std::pair<Elf64_Addr, std::string>> getRelaAddrs(elfio &reader, std::string section_name)
{
  std::vector<std::pair<Elf64_Addr, std::string>> relaAddrs;
  Elf_Half sec_num = reader.sections.size();
  for (int i = 0; i < sec_num; ++i)
  {
    section *psec = reader.sections[i];
    const relocation_section_accessor symbols(reader, psec);
    if (psec->get_name() == section_name)
    {
      for (unsigned int j = 0; j < symbols.get_entries_num(); ++j)
      {
        Elf64_Addr offset;
        Elf64_Addr symbolValue;
        std::string symbolName;
        unsigned type;
        Elf_Sxword addend;
        Elf_Sxword calcValue;
        symbols.get_entry(j, offset, symbolValue, symbolName, type, addend, calcValue);
        relaAddrs.push_back(std::make_pair(offset, symbolName));
      }
    }
  }
  return relaAddrs;
}

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    std::cout << "Usage: tutorial <elf_file>" << std::endl;
    return 1;
  }

  // Create an elfio reader
  elfio reader;

  // Load ELF data
  if (!reader.load(argv[1]))
  {
    std::cout << "Can't find or process ELF file " << argv[1] << std::endl;
    return 2;
  }

  std::string section_name = ".rela.plt";
  auto relaAddrs = getRelaAddrs(reader, section_name);
  auto min_addr = std::min_element(relaAddrs.begin(), relaAddrs.end(), [](const auto &a, const auto &b)
                                   { return a.first < b.first; });
  auto max_addr = std::max_element(relaAddrs.begin(), relaAddrs.end(), [](const auto &a, const auto &b)
                                   { return a.first < b.first; });
  auto max_length = std::max_element(relaAddrs.begin(), relaAddrs.end(), [](const auto &a, const auto &b)
                                     { return a.second.length() < b.second.length(); });

  std::cout << "GOT range: " << std::setw(12) << std::setfill('0') << std::hex << min_addr->first << " ~ " << std::setw(12) << std::setfill('0') << std::hex << max_addr->first << "\n\n";
  std::cout << "Offset" << std::string(10, ' ') << "Symbol name"
            << "\n";
  std::cout << std::string(12 + 4 + max_length->second.length(), '-') << "\n";
  for (auto &addr : relaAddrs)
  {
    std::cout << std::setw(12) << std::setfill('0') << std::hex << addr.first << std::string(4, ' ') << addr.second << "\n";
  }
  return 0;
}