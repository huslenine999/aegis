from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.sandbox import (
    is_docker_available,
    detect_port_from_file,
    scaffold_sandbox_context,
    run_sandbox_container
)

def test_detect_port_from_file(tmp_path):
    # Test file specifying port
    f1 = tmp_path / "app1.py"
    f1.write_text("app.run(port=8080)")
    assert detect_port_from_file(f1) == 8080

    # Test file specifying port with spaces
    f2 = tmp_path / "app2.py"
    f2.write_text("app.run(  host='0.0.0.0',   port  =  9000  )")
    assert detect_port_from_file(f2) == 9000

    # Test default fallback
    f3 = tmp_path / "app3.py"
    f3.write_text("print('hello')")
    assert detect_port_from_file(f3) == 5001

def test_is_docker_available_not_found():
    with patch("shutil.which", return_value=None):
        assert is_docker_available() is False

def test_is_docker_available_daemon_down():
    with patch("shutil.which", return_value="/usr/bin/docker"), \
         patch("subprocess.run") as mock_run:
        # Mock docker ps returning exit code 1
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result
        assert is_docker_available() is False

def test_is_docker_available_running():
    with patch("shutil.which", return_value="/usr/bin/docker"), \
         patch("subprocess.run") as mock_run:
        # Mock docker ps returning exit code 0
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        assert is_docker_available() is True

def test_scaffold_sandbox_context_custom_file(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("app.run(port=4000)")
    temp_dir = tmp_path / "sandbox_context"
    
    port = scaffold_sandbox_context(target, temp_dir)
    assert port == 4000
    assert (temp_dir / "Dockerfile").exists()
    assert (temp_dir / "app.py").exists()
    assert (temp_dir / "requirements.txt").exists()
    assert "semgrep" not in (temp_dir / "requirements.txt").read_text()
    
    dockerfile_content = (temp_dir / "Dockerfile").read_text()
    assert "EXPOSE 4000" in dockerfile_content
    assert "USER 10001:10001" in dockerfile_content
    assert "COPY --chown=10001:10001 app.py ." in dockerfile_content
    assert "CMD [\"python\", \"app.py\"]" in dockerfile_content

def test_scaffold_sandbox_context_local_app(tmp_path):
    # Setup mock local app structure
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (tmp_path / "requirements.txt").write_text("Flask==3.1.3\n")
    main_file = app_dir / "main.py"
    main_file.write_text("app.run(port=5001)")
    (app_dir / "database.py").write_text("print('db')")
    
    temp_dir = tmp_path / "sandbox_context"
    
    port = scaffold_sandbox_context(main_file, temp_dir)
    assert port == 5001
    assert (temp_dir / "Dockerfile").exists()
    assert (temp_dir / "app" / "main.py").exists()
    assert (temp_dir / "app" / "database.py").exists()
    assert (temp_dir / "requirements.txt").read_text() == "Flask==3.1.3\n"
    
    dockerfile_content = (temp_dir / "Dockerfile").read_text()
    assert "EXPOSE 5001" in dockerfile_content
    assert "USER 10001:10001" in dockerfile_content
    assert "COPY --chown=10001:10001 app/ app/" in dockerfile_content
    assert "CMD [\"python\", \"app/main.py\"]" in dockerfile_content

def test_run_sandbox_container_args():
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        success = run_sandbox_container(
            image_tag="test-image",
            container_name="test-container",
            host_port=5002,
            container_port=5001,
            waf_enabled=True
        )
        assert success is True
        
        # Verify docker run command arguments
        called_args = mock_run.call_args[0][0]
        assert "docker" in called_args
        assert "run" in called_args
        assert "--memory" in called_args
        assert "128m" in called_args
        assert "--cpus" in called_args
        assert "0.5" in called_args
        assert "--pids-limit" in called_args
        assert "50" in called_args
        assert "--cap-drop" in called_args
        assert "ALL" in called_args
        assert "--security-opt" in called_args
        assert "no-new-privileges:true" in called_args
        assert "--read-only" in called_args
        assert "--tmpfs" in called_args
        assert "/tmp:size=64m,mode=1777" in called_args
        assert "--user" in called_args
        assert "10001:10001" in called_args
        assert "WAF_ENABLED=true" in called_args

def test_run_scan_simulated_fallback():
    # Test main fastapi app routing when docker is down
    from app.main import app as fastapi_app
    client = TestClient(fastapi_app)
    
    with patch("app.main.is_docker_available", return_value=False):
        # Trigger scan
        response = client.post('/run-scan', json={"target": "secure"})
        assert response.status_code == 200
        assert response.json()['status'] == 'success'
        
        # Verify sandbox-status is simulated_fallback
        res_status = client.get('/get-scan-results')
        assert res_status.status_code == 200
        assert res_status.json()['sandbox_status'] == 'simulated_fallback'
