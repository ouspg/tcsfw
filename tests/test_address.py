from tcsfw.address import IPAddress, IPAddresses


def test_ip_address():
    ad = IPAddress.new("1.2.3.4")
    assert f"{ad}" == "1.2.3.4"
    assert ad.get_parseable_value() == "1.2.3.4"
    assert ad.is_null() is False
    assert ad.is_global() is True

    assert IPAddress.new("0.0.0.0") == IPAddresses.NULL
    assert IPAddresses.NULL.is_null() is True
    assert IPAddresses.NULL.is_global() is False

    assert IPAddress.new("192.168.1.1").is_global() is False
