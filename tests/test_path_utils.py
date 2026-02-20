"""Tests for path_utils module."""

from pathlib import Path

from py3signer.path_utils import (
    get_keystore_filename,
    get_keystore_paths,
    get_password_filename,
    get_pubkey_from_filename,
    scan_keystore_directories,
    scan_keystore_directory,
)


class TestGetKeystoreFilename:
    """Tests for get_keystore_filename function."""

    def test_basic_pubkey(self) -> None:
        """Test with basic lowercase hex string."""
        assert get_keystore_filename("aabbccdd") == "aabbccdd.json"

    def test_uppercase_pubkey(self) -> None:
        """Test that uppercase pubkey is normalized to lowercase."""
        assert get_keystore_filename("AABBCCDD") == "aabbccdd.json"

    def test_mixed_case_pubkey(self) -> None:
        """Test that mixed case pubkey is normalized to lowercase."""
        assert get_keystore_filename("AaBbCcDd") == "aabbccdd.json"

    def test_full_pubkey(self) -> None:
        """Test with full 96-character pubkey (48 bytes)."""
        pubkey = "aabbccdd" * 12  # 96 characters
        assert get_keystore_filename(pubkey) == f"{pubkey}.json"


class TestGetPasswordFilename:
    """Tests for get_password_filename function."""

    def test_basic_pubkey(self) -> None:
        """Test with basic lowercase hex string."""
        assert get_password_filename("aabbccdd") == "aabbccdd.txt"

    def test_uppercase_pubkey(self) -> None:
        """Test that uppercase pubkey is normalized to lowercase."""
        assert get_password_filename("AABBCCDD") == "aabbccdd.txt"

    def test_mixed_case_pubkey(self) -> None:
        """Test that mixed case pubkey is normalized to lowercase."""
        assert get_password_filename("AaBbCcDd") == "aabbccdd.txt"


class TestGetKeystorePaths:
    """Tests for get_keystore_paths function."""

    def test_basic_paths(self) -> None:
        """Test generating paths with basic inputs."""
        directory = Path("/some/dir")
        keystore_path, password_path = get_keystore_paths(directory, "AABBCCDD")

        assert keystore_path == Path("/some/dir/aabbccdd.json")
        assert password_path == Path("/some/dir/aabbccdd.txt")

    def test_full_pubkey_paths(self) -> None:
        """Test generating paths with full pubkey."""
        directory = Path("/keystores")
        pubkey = "ABCDEF" * 16  # 96 characters
        keystore_path, password_path = get_keystore_paths(directory, pubkey)

        expected_base = pubkey.lower()
        assert keystore_path == Path(f"/keystores/{expected_base}.json")
        assert password_path == Path(f"/keystores/{expected_base}.txt")


class TestGetPubkeyFromFilename:
    """Tests for get_pubkey_from_filename function."""

    def test_keystore_filename(self) -> None:
        """Test extracting pubkey from keystore filename."""
        assert get_pubkey_from_filename("aabbccdd.json") == "aabbccdd"

    def test_password_filename(self) -> None:
        """Test extracting pubkey from password filename."""
        assert get_pubkey_from_filename("aabbccdd.txt") == "aabbccdd"

    def test_uppercase_filename(self) -> None:
        """Test extracting pubkey from uppercase filename."""
        assert get_pubkey_from_filename("AABBCCDD.JSON") == "aabbccdd"

    def test_non_matching_extension(self) -> None:
        """Test that non-matching extensions return None."""
        assert get_pubkey_from_filename("aabbccdd.yaml") is None
        assert get_pubkey_from_filename("aabbccdd") is None

    def test_empty_filename(self) -> None:
        """Test that empty filename returns None."""
        assert get_pubkey_from_filename("") is None


class TestScanKeystoreDirectory:
    """Tests for scan_keystore_directory function."""

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Test scanning an empty directory."""
        result = scan_keystore_directory(tmp_path)
        assert result == {}

    def test_directory_with_matching_pairs(self, tmp_path: Path) -> None:
        """Test directory with matching keystore/password pairs."""
        # Create matching pairs
        (tmp_path / "keystore1.json").write_text("{}")
        (tmp_path / "keystore1.txt").write_text("password1")
        (tmp_path / "keystore2.json").write_text("{}")
        (tmp_path / "keystore2.txt").write_text("password2")

        result = scan_keystore_directory(tmp_path)

        assert len(result) == 2
        assert "keystore1" in result
        assert "keystore2" in result
        assert result["keystore1"] == tmp_path / "keystore1.json"
        assert result["keystore2"] == tmp_path / "keystore2.json"

    def test_directory_with_missing_password(self, tmp_path: Path) -> None:
        """Test that keystores without password files are skipped."""
        (tmp_path / "keystore1.json").write_text("{}")
        (tmp_path / "keystore1.txt").write_text("password1")
        (tmp_path / "keystore2.json").write_text("{}")  # No password file

        result = scan_keystore_directory(tmp_path)

        assert len(result) == 1
        assert "keystore1" in result
        assert "keystore2" not in result

    def test_directory_with_extra_files(self, tmp_path: Path) -> None:
        """Test that non-json files are ignored."""
        (tmp_path / "keystore.json").write_text("{}")
        (tmp_path / "keystore.txt").write_text("password")
        (tmp_path / "readme.md").write_text("# README")
        (tmp_path / "data.csv").write_text("a,b,c")

        result = scan_keystore_directory(tmp_path)

        assert len(result) == 1
        assert "keystore" in result

    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        """Test scanning a non-existent directory."""
        nonexistent = tmp_path / "does_not_exist"
        result = scan_keystore_directory(nonexistent)
        assert result == {}

    def test_file_instead_of_directory(self, tmp_path: Path) -> None:
        """Test passing a file instead of a directory."""
        file_path = tmp_path / "some_file.txt"
        file_path.write_text("content")
        result = scan_keystore_directory(file_path)
        assert result == {}


class TestScanKeystoreDirectories:
    """Tests for scan_keystore_directories function."""

    def test_empty_directories(self, tmp_path: Path) -> None:
        """Test scanning empty directories."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        result = scan_keystore_directories(keystores_dir, passwords_dir)
        assert result == {}

    def test_matching_pairs_in_separate_dirs(self, tmp_path: Path) -> None:
        """Test finding matching pairs in separate directories."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        (keystores_dir / "key1.json").write_text("{}")
        (passwords_dir / "key1.txt").write_text("pass1")
        (keystores_dir / "key2.json").write_text("{}")
        (passwords_dir / "key2.txt").write_text("pass2")

        result = scan_keystore_directories(keystores_dir, passwords_dir)

        assert len(result) == 2
        assert "key1" in result
        assert "key2" in result
        assert result["key1"] == (
            keystores_dir / "key1.json",
            passwords_dir / "key1.txt",
        )
        assert result["key2"] == (
            keystores_dir / "key2.json",
            passwords_dir / "key2.txt",
        )

    def test_missing_password_in_separate_dir(self, tmp_path: Path) -> None:
        """Test that keystores without matching password files are skipped."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        (keystores_dir / "key1.json").write_text("{}")
        (passwords_dir / "key1.txt").write_text("pass1")
        (keystores_dir / "key2.json").write_text("{}")  # No password file

        result = scan_keystore_directories(keystores_dir, passwords_dir)

        assert len(result) == 1
        assert "key1" in result
        assert "key2" not in result

    def test_nonexistent_keystores_dir(self, tmp_path: Path) -> None:
        """Test with non-existent keystores directory."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        passwords_dir.mkdir()

        result = scan_keystore_directories(keystores_dir, passwords_dir)
        assert result == {}

    def test_nonexistent_passwords_dir(self, tmp_path: Path) -> None:
        """Test with non-existent passwords directory - still finds keystores."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()

        (keystores_dir / "key1.json").write_text("{}")

        # The function checks if password file exists, so if passwords_dir doesn't exist,
        # no matches will be found
        result = scan_keystore_directories(keystores_dir, passwords_dir)
        assert result == {}
