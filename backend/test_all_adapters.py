"""Test all adapters for double WSL nesting bug fix"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.adapters.nikto_adapter import NiktoAdapter
from services.adapters.nmap_adapter import NmapAdapter
from services.adapters.nuclei_adapter import NucleiAdapter
from services.adapters.openvas_adapter import OpenVASAdapter
from utils.wsl_helper import WSLHelper

def test_adapter(adapter_name, adapter, target, scan_type, options=None):
    """Test a single adapter"""
    print(f"\n{'='*100}")
    print(f"Testing {adapter_name} Adapter")
    print(f"{'='*100}")
    
    try:
        # Test 1: Build command
        print(f"✓ Building command for {scan_type} scan of {target}...")
        if options:
            command = adapter.build_command(target, scan_type, options)
        else:
            command = adapter.build_command(target, scan_type, adapter.get_default_options())
        
        # Test 2: Verify it's an array
        if not isinstance(command, list):
            print(f"❌ FAILED: Command should be a list, got {type(command)}")
            return False
        print(f"✓ Command is a list (correct)")
        
        # Test 3: Check for single WSL call
        wsl_count = sum(1 for part in command if 'wsl.exe' in str(part).lower())
        if wsl_count != 1:
            print(f"❌ FAILED: Expected 1 wsl.exe call, found {wsl_count}")
            print(f"   Command: {command}")
            return False
        print(f"✓ Single WSL call (no double nesting)")
        
        # Test 4: Check for bash -c (should NOT be present in array)
        has_bash_c = any('bash' in str(part) and '-c' in str(part) for part in command)
        if has_bash_c:
            print(f"❌ FAILED: Found 'bash -c' in command (indicates wrapping)")
            print(f"   Command: {command}")
            return False
        print(f"✓ No 'bash -c' wrapping")
        
        # Test 5: Verify WSL command structure
        if command[0] != 'wsl.exe':
            print(f"❌ FAILED: First element should be 'wsl.exe', got '{command[0]}'")
            return False
        if command[1] != '-d' or command[2] != 'kali-linux':
            print(f"❌ FAILED: Expected '-d kali-linux', got '{command[1]} {command[2]}'")
            return False
        if command[3] != '--':
            print(f"❌ FAILED: Expected '--' separator, got '{command[3]}'")
            return False
        print(f"✓ WSL command structure correct")
        
        # Test 6: Verify tool name
        expected_tool = adapter.tool_name
        actual_tool = command[4]
        
        # Special case: OpenVAS uses python3 to run a script
        if adapter_name == 'OpenVAS' and actual_tool == 'python3':
            print(f"✓ Tool name correct: python3 (OpenVAS uses python3 to run gvm_scan_script.py)")
        elif actual_tool != expected_tool:
            print(f"❌ FAILED: Expected tool '{expected_tool}', got '{actual_tool}'")
            return False
        else:
            print(f"✓ Tool name correct: {expected_tool}")
        
        # Display command preview
        cmd_str = ' '.join(command)
        print(f"\n📋 Command preview:")
        print(f"   {cmd_str[:150]}...")
        
        print(f"\n✅ {adapter_name} adapter passed all tests!")
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_wsl_helper():
    """Test WSL helper has the new method"""
    print(f"\n{'='*100}")
    print(f"Testing WSL Helper")
    print(f"{'='*100}")
    
    wsl = WSLHelper()
    
    # Check for new method
    if not hasattr(wsl, 'execute_wsl_command_array'):
        print(f"❌ FAILED: execute_wsl_command_array method not found")
        return False
    print(f"✓ execute_wsl_command_array method exists")
    
    # Check method signature
    import inspect
    sig = inspect.signature(wsl.execute_wsl_command_array)
    params = list(sig.parameters.keys())
    expected_params = ['wsl_command', 'timeout', 'check_success']
    if params != expected_params:
        print(f"❌ FAILED: Method signature incorrect")
        print(f"   Expected: {expected_params}")
        print(f"   Got: {params}")
        return False
    print(f"✓ Method signature correct")
    
    print(f"\n✅ WSL Helper passed all tests!")
    return True

def main():
    print("\n" + "="*100)
    print("ADAPTER VALIDATION TEST SUITE")
    print("Testing for Double WSL Nesting Bug Fix")
    print("="*100)
    
    results = {}
    
    # Test WSL Helper first
    results['WSLHelper'] = test_wsl_helper()
    
    # Test Nikto
    try:
        nikto = NiktoAdapter()
        results['Nikto'] = test_adapter(
            'Nikto', 
            nikto, 
            'http://testphp.vulnweb.com', 
            'quick'
        )
    except Exception as e:
        print(f"❌ Nikto initialization failed: {e}")
        results['Nikto'] = False
    
    # Test Nmap
    try:
        nmap = NmapAdapter()
        results['Nmap'] = test_adapter(
            'Nmap', 
            nmap, 
            '192.168.1.1', 
            'basic',
            nmap.get_default_options()
        )
    except Exception as e:
        print(f"❌ Nmap initialization failed: {e}")
        results['Nmap'] = False
    
    # Test Nuclei
    try:
        nuclei = NucleiAdapter()
        results['Nuclei'] = test_adapter(
            'Nuclei', 
            nuclei, 
            'http://testphp.vulnweb.com', 
            'quick'
        )
    except Exception as e:
        print(f"❌ Nuclei initialization failed: {e}")
        results['Nuclei'] = False
    
    # Test OpenVAS
    try:
        openvas = OpenVASAdapter()
        results['OpenVAS'] = test_adapter(
            'OpenVAS', 
            openvas, 
            '192.168.1.1', 
            'basic',
            openvas.get_default_options()
        )
    except Exception as e:
        print(f"❌ OpenVAS initialization failed: {e}")
        results['OpenVAS'] = False
    
    # Summary
    print(f"\n{'='*100}")
    print("TEST SUMMARY")
    print(f"{'='*100}")
    
    for name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{status} - {name}")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Double WSL nesting bug is fixed.")
        return 0
    else:
        print("\n⚠️ SOME TESTS FAILED! Review errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
