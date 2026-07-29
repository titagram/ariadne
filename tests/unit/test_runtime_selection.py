from ariadne.runtime.selection import RuntimeChoice, choose_runtime


def test_banal_available_tool_stays_local() -> None:
    assert (
        choose_runtime(("scan.tcp",), local_tool_available=True)
        is RuntimeChoice.LOCAL
    )


def test_specialist_missing_tool_escalates_to_kali() -> None:
    assert (
        choose_runtime(("pivot.route",), local_tool_available=False)
        is RuntimeChoice.KALI
    )


def test_missing_banal_tool_blocks_without_starting_kali() -> None:
    assert (
        choose_runtime(("scan.tcp",), local_tool_available=False)
        is RuntimeChoice.BLOCKED
    )
