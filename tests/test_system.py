"""
System tests for capfile using pytest.

These tests verify the capfile binary works correctly by invoking it
as a subprocess and checking its output.
"""

import subprocess
import os
import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SIMPLE_PCAP = os.path.join(FIXTURES_DIR, "simple.pcap")
SIMPLE_PCAPNG = os.path.join(FIXTURES_DIR, "simple.pcapng")


def run_capfile(args, check=True):
    """Run capfile CLI and return result."""
    result = subprocess.run(
        ["cargo", "run", "--"] + args,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        pytest.fail(f"capfile failed: {result.stderr}")
    return result


class TestCapfileInfo:
    """Tests for the 'capfile info' command."""
    
    def test_info_pcap(self):
        """Test info command on PCAP file."""
        result = run_capfile(["info", SIMPLE_PCAP], check=False)
        assert result.returncode == 0
        assert "Format: PCAP" in result.stdout
        assert "Link type: 1" in result.stdout
    
    def test_info_pcapng(self):
        """Test info command on PCAPNG file."""
        result = run_capfile(["info", SIMPLE_PCAPNG], check=False)
        # May have issues with pcapng parsing
        assert result.returncode == 0
    
    def test_info_missing_file(self):
        """Test info command with missing file."""
        result = run_capfile(["info", "/nonexistent.pcap"], check=False)
        assert result.returncode != 0


class TestCapfileList:
    """Tests for the 'capfile list' command."""
    
    def test_list_pcap(self):
        """Test list command on PCAP file."""
        result = run_capfile(["list", SIMPLE_PCAP], check=False)
        assert result.returncode == 0
        assert "Total packets:" in result.stdout
    
    def test_list_pcapng(self):
        """Test list command on PCAPNG file."""
        result = run_capfile(["list", SIMPLE_PCAPNG], check=False)
        # May have issues with pcapng parsing
        assert result.returncode == 0
    
    def test_list_missing_file(self):
        """Test list command with missing file."""
        result = run_capfile(["list", "/nonexistent.pcap"], check=False)
        assert result.returncode != 0


class TestCapfileHelp:
    """Tests for help/usage."""
    
    def test_no_args_shows_help(self):
        """Test running with no arguments shows usage."""
        result = run_capfile([], check=False)
        assert result.returncode != 0
        assert "Usage:" in result.stdout or "capfile" in result.stdout.lower()
    
    def test_unknown_command(self):
        """Test unknown command shows error."""
        result = run_capfile(["unknown"], check=False)
        assert result.returncode != 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])