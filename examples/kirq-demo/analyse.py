import os
import json
import sys
from collections import defaultdict

class CodebaseAnalyzer:
    def __init__(self, root_dir):
        self.root_dir = os.path.abspath(root_dir)
        self.src_files = {}
        self.cert_files = defaultdict(list)
        self.data_files = []
        self.dependencies = set()
        
    def analyze_src_code(self):
        src_dir = os.path.join(self.root_dir, 'src')
        print(f"Looking for source files in: {src_dir}")
        if not os.path.exists(src_dir):
            print("Source directory not found!")
            return
        
        for file in os.listdir(src_dir):
            if file.endswith('.py'):
                file_path = os.path.join(src_dir, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        self.src_files[file] = {
                            'lines': len(content.splitlines()),
                            'imports': self._extract_imports(content),
                            'functions': self._count_functions(content)
                        }
                except Exception as e:
                    print(f"Error reading {file}: {str(e)}")
                    
    def analyze_certificates(self):
        cert_dir = os.path.join(self.root_dir, 'certificate')
        print(f"Looking for certificates in: {cert_dir}")
        if not os.path.exists(cert_dir):
            print("Certificate directory not found!")
            return
            
        for root, dirs, files in os.walk(cert_dir):
            try:
                vendor = root.split(os.path.sep)[root.split(os.path.sep).index('certificate') + 1]
                for file in files:
                    if file.endswith(('.pem', '.p12', '.jks')):
                        self.cert_files[vendor].append(file)
            except IndexError:
                continue  # Skip if we can't determine vendor (root directory)
                    
    def analyze_dependencies(self):
        req_file = os.path.join(self.root_dir, 'src', 'requirements.txt')
        print(f"Looking for requirements in: {req_file}")
        if os.path.exists(req_file):
            try:
                with open(req_file, 'r', encoding='utf-8') as f:
                    self.dependencies = set(line.strip() for line in f if line.strip())
            except Exception as e:
                print(f"Error reading requirements.txt: {str(e)}")
        else:
            print("Requirements.txt not found!")
                
    def _extract_imports(self, content):
        imports = []
        for line in content.splitlines():
            if line.strip().startswith(('import ', 'from ')):
                imports.append(line.strip())
        return imports
        
    def _count_functions(self, content):
        return len([line for line in content.splitlines() if line.strip().startswith('def ')])
        
    def generate_report(self):
        report = {
            "source_code_analysis": {
                "total_files": len(self.src_files),
                "files_detail": self.src_files
            },
            "certificate_analysis": {
                "vendors": dict(self.cert_files),
                "total_certificates": sum(len(certs) for certs in self.cert_files.values())
            },
            "dependencies": list(self.dependencies)
        }
        return report

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analyse.py <project_root_directory>")
        sys.exit(1)
        
    project_root = sys.argv[1]
    if not os.path.exists(project_root):
        print(f"Error: Directory '{project_root}' does not exist!")
        sys.exit(1)
        
    print(f"\nAnalyzing project at: {os.path.abspath(project_root)}\n")
    
    analyzer = CodebaseAnalyzer(project_root)
    analyzer.analyze_src_code()
    analyzer.analyze_certificates()
    analyzer.analyze_dependencies()
    
    report = analyzer.generate_report()
    
    print("\n=== QKD Demo Codebase Analysis Report ===\n")
    print(f"Source Files: {report['source_code_analysis']['total_files']}")
    
    if report['source_code_analysis']['files_detail']:
        print("\nSource Code Details:")
        for file, details in report['source_code_analysis']['files_detail'].items():
            print(f"\n{file}:")
            print(f"  Lines: {details['lines']}")
            print(f"  Functions: {details['functions']}")
            print("  Imports:")
            for imp in details['imports']:
                print(f"    {imp}")
        
    if report['certificate_analysis']['vendors']:
        print("\nCertificate Analysis:")
        for vendor, certs in report['certificate_analysis']['vendors'].items():
            print(f"\n{vendor}: {len(certs)} certificates")
            for cert in certs:
                print(f"  - {cert}")
        
    if report['dependencies']:
        print("\nDependencies:")
        for dep in report['dependencies']:
            print(f"  - {dep}")

if __name__ == "__main__":
    main()
