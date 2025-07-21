import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

banner = '''

                  __  '                 ,.-~·-.,__,.-::^·- .,'   ‘        ',:'/¯/`:,     ,:´'*:^-:´¯'`:·,         ‘       
            ,·:'´/::::/'`;·.,           /:::::::::::::::::::::::::/'; '       /:/_/::::/';'  '/::::/::::::::::;¯'`*:^:-.,  ‘   
        .:´::::/::::/:::::::`;       /;:·–– :;:::::_ ;: – .,/::;i'‘      /:'     '`:/::;‘/·´'*^-·´¯'`^·,/::::::::::::'`:,   
       /:;:· '´ ¯¯'`^·-;::::/' ‘    /´          ¯¯           ';::/        ;         ';:';‘'`,             ¯'`*^·-:;::::::'\' ‘
      /·´           _   '`;/‘     ,:                          ,:/          |         'i::i   '`·,                     '`·;:::i'‘
     'i            ;::::'`;*       ';_,..–-.,_     _    _,.·´‘           ';        ;'::i      '|       .,_             \:'/' 
      `;           '`;:::::'`:,             ,·´'    '`·;'i¯                  'i        'i::i'      'i       'i:::'`·,          i/' ‘
        `·,           '`·;:::::';           i         'i:i'       ’            ;       'i::;'      'i       'i::/:,:          /'   
      ,~:-'`·,           `:;::/'           ';        ';:i'     ’              ';       i:/'        ;      ,'.^*'´     _,.·´‘    
     /:::::::::';           ';/              i        i:/'                     ';     ;/ °        ';     ;/ '`*^*'´¯           
   ,:~·- . -·'´          ,'´                 ;      i/    °                   ';   / °           \    /                      
   '`·,               , ·'´                    \   '/'                           `'´       °        '`^'´‘                      
        '`*^·–·^*'´'           ‘                ¯               °              ‘                                            
                                                                                                        @AbdulMubinDev
'''




# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ioc_parser import IOCParser

class STIP:
    def __init__(self):
        self.parser = IOCParser()
        self.data_dir = Path("data")
        self.results_file = "results.json"
        self.iocs_storage = self.data_dir / "iocs.json"
        
        # Ensure data directory exists
        self.data_dir.mkdir(exist_ok=True)
    
    def read_file(self, file_path: str) -> str:
        """Read text from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            print(f"❌ Error: File '{file_path}' not found")
            return ""
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return ""
    
    def save_json(self, data: dict, filename: str):
        """Save data to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"✅ Results saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving file: {e}")
    
    def load_existing_iocs(self) -> dict:
        """Load existing IOCs from storage"""
        if self.iocs_storage.exists():
            try:
                with open(self.iocs_storage, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Warning: Could not load existing IOCs: {e}")
        
        return {"sessions": []}
    
    def merge_iocs(self, existing: dict, new_iocs: dict) -> dict:
        """Merge new IOCs with existing ones"""
        # Create a new session entry
        session = {
            "timestamp": datetime.now().isoformat(),
            "source": "CLI collection",
            "iocs": new_iocs
        }
        
        existing["sessions"].append(session)
        return existing
    
    def display_results(self, iocs: dict, source: str = ""):
        """Display IOC extraction results"""
        print("\n" + "="*60)
        print("🛡️  STIP - Threat Intelligence Collection Results")
        if source:
            print(f"📁 Source: {source}")
        print("="*60)
        
        if iocs['total_count'] == 0:
            print("ℹ️  No IOCs found in the provided text")
            return
        
        print(f"📊 Total IOCs Found: {iocs['total_count']}")
        print("-" * 60)
        
        # Display IPs
        if iocs['ips']:
            print(f"🌐 IP Addresses ({len(iocs['ips'])}):")
            for ip in sorted(iocs['ips']):
                print(f"   • {ip}")
            print()
        
        # Display Hashes
        for hash_type, hashes in iocs['hashes'].items():
            if hashes:
                print(f"🔐 {hash_type.upper()} Hashes ({len(hashes)}):")
                for hash_val in sorted(hashes):
                    print(f"   • {hash_val}")
                print()
        
        # Display URLs
        if iocs['urls']:
            print(f"🔗 URLs ({len(iocs['urls'])}):")
            for url in sorted(iocs['urls']):
                print(f"   • {url}")
            print()
        
        # Display Domains
        if iocs['domains']:
            print(f"🌍 Domains ({len(iocs['domains'])}):")
            for domain in sorted(iocs['domains']):
                print(f"   • {domain}")
            print()
        
        print("="*60)
    
    def process_text(self, text: str, source: str = "") -> dict:
        """Process text and extract IOCs"""
        if not text.strip():
            print("⚠️  Warning: No text provided for processing")
            return {}
        
        print("🔍 Analyzing text for IOCs...")
        iocs = self.parser.extract_iocs(text)
        
        # Display results
        self.display_results(iocs, source)
        
        # Prepare results with metadata
        results = {
            "timestamp": datetime.now().isoformat(),
            "source": source or "text input",
            "iocs": iocs,
            "metadata": {
                "text_length": len(text),
                "processing_tool": "STIP CLI MVP v1.0"
            }
        }
        
        return results
    
    def process_file(self, file_path: str) -> dict:
        """Process file and extract IOCs"""
        print(f"📂 Reading file: {file_path}")
        text = self.read_file(file_path)
        
        if not text:
            return {}
        
        return self.process_text(text, file_path)
    
    def run_sample(self):
        """Run with sample OSINT data"""
        sample_file = self.data_dir / "sample_osint.txt"
        
        if not sample_file.exists():
            print(f"❌ Sample file not found: {sample_file}")
            print("Please ensure sample_osint.txt exists in the data/ directory")
            return
        
        results = self.process_file(str(sample_file))
        
        if results:
            # Save results
            self.save_json(results, self.results_file)
            
            # Update IOC storage
            existing_iocs = self.load_existing_iocs()
            updated_iocs = self.merge_iocs(existing_iocs, results['iocs'])
            self.save_json(updated_iocs, str(self.iocs_storage))
    
    def run_interactive(self):
        """Run in interactive mode"""
        print("🛡️  STIP - Interactive Mode")
        print("Enter text to analyze (press Ctrl+D when finished):")
        print("-" * 40)
        
        try:
            lines = []
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass
        
        text = '\n'.join(lines)
        results = self.process_text(text, "interactive input")
        
        if results:
            # Save results
            self.save_json(results, self.results_file)
            
            # Update IOC storage
            existing_iocs = self.load_existing_iocs()
            updated_iocs = self.merge_iocs(existing_iocs, results['iocs'])
            self.save_json(updated_iocs, str(self.iocs_storage))

def main():
    
    print(banner)
    parser = argparse.ArgumentParser(
        description="STIP - Smart Threat Intelligence Platform CLI MVP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python stip.py --sample                    # Process sample OSINT data
  python stip.py --file data/threat.txt      # Process specific file
  python stip.py --interactive               # Interactive text input
        """
    )
    
    parser.add_argument('--sample', action='store_true',
                       help='Process sample OSINT data from data/sample_osint.txt')
    parser.add_argument('--file', type=str, metavar='PATH',
                       help='Process IOCs from specified file')
    parser.add_argument('--interactive', action='store_true',
                       help='Interactive mode - enter text manually')
    
    args = parser.parse_args()
    
    stip = STIP()
    
    if args.sample:
        stip.run_sample()
    elif args.file:
        results = stip.process_file(args.file)
        if results:
            stip.save_json(results, stip.results_file)
            existing_iocs = stip.load_existing_iocs()
            updated_iocs = stip.merge_iocs(existing_iocs, results['iocs'])
            stip.save_json(updated_iocs, str(stip.iocs_storage))
    elif args.interactive:
        stip.run_interactive()
    else:
        parser.print_help()
        print("\n💡 Tip: Start with --sample to test with sample data")

if __name__ == "__main__":
    main()
