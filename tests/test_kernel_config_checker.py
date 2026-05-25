from agent.tools.kernel_config_checker import KernelConfigChecker


def test_detects_disabled_ublk_direct_object(tmp_path):
    source = tmp_path / "linux"
    (source / "drivers" / "block").mkdir(parents=True)
    (source / ".config").write_text("# CONFIG_BLK_DEV_UBLK is not set\n")
    (source / "drivers" / "block" / "Makefile").write_text(
        "obj-$(CONFIG_BLK_DEV_UBLK) += ublk_drv.o\n"
    )

    result = KernelConfigChecker(str(source)).check_files(["drivers/block/ublk_drv.c"])

    assert result["skipped"] is True
    assert result["failure_mode"] == "config.module_disabled"
    assert result["disabled"][0]["config_symbols"][0]["symbol"] == "CONFIG_BLK_DEV_UBLK"


def test_detects_disabled_bluetooth_parent_directory(tmp_path):
    source = tmp_path / "linux"
    (source / "net" / "bluetooth").mkdir(parents=True)
    (source / ".config").write_text("# CONFIG_BT is not set\n")
    (source / "net" / "Makefile").write_text("obj-$(CONFIG_BT) += bluetooth/\n")

    result = KernelConfigChecker(str(source)).check_files(["net/bluetooth/hci_core.c"])

    assert result["skipped"] is True
    assert result["disabled"][0]["config_symbols"][0]["symbol"] == "CONFIG_BT"


def test_mixed_patch_with_build_relevant_file_is_not_skipped(tmp_path):
    source = tmp_path / "linux"
    (source / "drivers" / "block").mkdir(parents=True)
    (source / "fs").mkdir(parents=True)
    (source / ".config").write_text("# CONFIG_BLK_DEV_UBLK is not set\n")
    (source / "drivers" / "block" / "Makefile").write_text(
        "obj-$(CONFIG_BLK_DEV_UBLK) += ublk_drv.o\n"
    )

    result = KernelConfigChecker(str(source)).check_files([
        "drivers/block/ublk_drv.c", "fs/read_write.c",
    ])

    assert result["disabled"][0]["path"] == "drivers/block/ublk_drv.c"
    assert result["skipped"] is False
