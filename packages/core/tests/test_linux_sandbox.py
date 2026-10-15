"""Linux backend selection fails closed; platform enforcement is tested in Docker."""
from pathlib import Path

import pytest
from redjohn_core import executor, linux_sandbox
from redjohn_core.errors import RJError


def test_missing_landlock_never_falls_back_to_unrestricted_exec(monkeypatch, tmp_path):
    monkeypatch.setattr(executor.sys, 'platform', 'linux')
    monkeypatch.setattr(linux_sandbox, 'abi_version', lambda: 2)
    monkeypatch.setattr(linux_sandbox.ctypes.util, 'find_library', lambda _: 'libseccomp.so.2')
    assert executor.executor_capability()['available'] is False
    with pytest.raises(RJError, match='Landlock ABI'):
        executor.sandbox_command(['/bin/echo','unsafe'],tmp_path)


def test_missing_seccomp_never_uses_landlock_alone(monkeypatch, tmp_path):
    monkeypatch.setattr(executor.sys, 'platform', 'linux')
    monkeypatch.setattr(linux_sandbox, 'abi_version', lambda: 4)
    monkeypatch.setattr(linux_sandbox.ctypes.util, 'find_library', lambda _: None)
    with pytest.raises(RJError, match='libseccomp2'):
        executor.sandbox_command(['/bin/echo','unsafe'],tmp_path)


def test_frozen_linux_uses_bundled_helper_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(executor.sys,'platform','linux')
    monkeypatch.setattr(executor.sys,'frozen',True,raising=False)
    monkeypatch.setattr(linux_sandbox,'capability',lambda:{'available':True})
    command=executor.sandbox_command(['/bin/echo','allowed'],tmp_path)
    assert command[:4]==[executor.sys.executable,'--sandbox-helper',str(tmp_path),'--']
    assert command[-1]=='allowed'


def test_python_linux_uses_isolated_child_not_preexec(monkeypatch,tmp_path):
    monkeypatch.setattr(executor.sys,'platform','linux')
    monkeypatch.delattr(executor.sys,'frozen',raising=False)
    monkeypatch.setattr(linux_sandbox,'capability',lambda:{'available':True})
    command=executor.sandbox_command(['/bin/echo','allowed'],tmp_path)
    assert command[1:3]==['-I','-S']
    assert Path(command[3]).name=='linux_sandbox.py'
    assert Path(command[3]).is_file()


def test_frozen_seccomp_uses_only_bundled_native_library(monkeypatch, tmp_path):
    monkeypatch.setattr(linux_sandbox.sys, '_MEIPASS', str(tmp_path), raising=False)
    monkeypatch.setattr(linux_sandbox.ctypes.util, 'find_library', lambda _: 'host-library')
    assert linux_sandbox._seccomp_library() is None
    bundled = tmp_path / 'libseccomp.so.2'
    bundled.write_bytes(b'fixture')
    assert linux_sandbox._seccomp_library() == str(bundled)


def test_selected_system_python_gets_only_its_standard_library(monkeypatch, tmp_path):
    monkeypatch.setattr(linux_sandbox.sysconfig, 'get_path', lambda _: str(tmp_path / 'bundle'))
    assert linux_sandbox._stdlib_paths(Path('/usr/local/bin/python3.12')) == {
        tmp_path / 'bundle', Path('/usr/local/lib/python3.12'),
    }
    assert linux_sandbox._stdlib_paths(tmp_path / 'bin/python3.12') == {tmp_path / 'bundle'}
    assert linux_sandbox._stdlib_paths(Path('/usr/local/bin/custom')) == {tmp_path / 'bundle'}
