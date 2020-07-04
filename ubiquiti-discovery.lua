
set_plugin_info({
  version = "0.1.0",
  description = "Ubiquiti Discovery Protocol Dissector - Discovery",
  author = "Luc-Edmond Gaspard",
  repository = "https://github.com/gaspardle/ubiquiti-protocol-dissector"
})

ubntdisc_protocol = Proto("UBDISC",  "UBNT Protocol - Discovery")

local pf = {
  version = ProtoField.uint8("ubnt.version", "Version", base.DEC),
  type = ProtoField.uint8("ubnt.type", "Type", base.HEX),
  message_length = ProtoField.uint16("ubnt.length", "Length", base.DEC),
  field_type = ProtoField.uint8("ubnt.field.type", "Type", base.HEX),
  field_length = ProtoField.uint16("ubnt.field.length", "Field length", base.DEC),

  field_mac = ProtoField.ether("ubnt.field.mac", "MAC Address"),
  field_ip = ProtoField.ipv4("ubnt.field.mac", "IP Address"),
  field_firmversion = ProtoField.string("ubnt.field.firmwareversion", "Version"),
  field_uptime = ProtoField.relative_time("ubnt.field.uptime", "Uptime"),
  field_hostname = ProtoField.string("ubnt.field.hostname", "Hostname"),
  field_platform = ProtoField.string("ubnt.field.platform", "Platform"),
  field_essid = ProtoField.string("ubnt.field.essid", "ESSID"),
  field_version = ProtoField.string("ubnt.field.version", "Version"),
  field_model =  ProtoField.string("ubnt.field.model", "Model"),
  field_default =  ProtoField.bool("ubnt.field.default", "Default"),
  field_locating =  ProtoField.bool("ubnt.field.field_locating", "Locating"),
  field_dhcpclient =  ProtoField.bool("ubnt.field.dhcpclient", "DHCP Client"),
  field_dhcpclientbound =  ProtoField.bool("ubnt.field.dhcpclientbound", "DHCP Client Bound"),
  field_serial = ProtoField.bytes("ubnt.field.serial", "Serial", base.NONE),
  field_seq = ProtoField.uint32("ubnt.field.seq", "Seq"),
  field_reqversion = ProtoField.string("ubnt.field.reqversion", "Required Firmware Version"),

  field_wmode = ProtoField.uint8("ubnt.field.wmode", "WMode"),
  field_username = ProtoField.string("ubnt.field.username", "Username"),
  field_salt = ProtoField.bytes("ubnt.field.salt", "Salt", base.NONE),
  field_rndchallenge = ProtoField.bytes("ubnt.field.rndchallenge", "Rnd Challenge", base.NONE),
  field_challenge = ProtoField.bytes("ubnt.field.challenge", "Challenge", base.NONE),
  field_sshdport = ProtoField.uint16("ubnt.field.sshdport", "SSHD Port", base.DEC),
  field_webui = ProtoField.string("ubnt.field.webui", "Web UI URL"),
  field_unknowndata = ProtoField.bytes("ubnt.field.unknowndata", "Unknown Data", base.NONE),

}

ubntdisc_protocol.fields = pf


function ubntdisc_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = ubntdisc_protocol.name

  local subtree = tree:add(ubntdisc_protocol, buffer(), "UBNT Discovery Protocol")
  subtree:add(pf.version, buffer(0,1))
  subtree:add(pf.type, buffer(1,1))
  subtree:add(pf.message_length, buffer(2,2))

  local offset = 4
  local len = buffer:len()

  while offset < len do
    local start_offset = offset
    local type_buf = buffer(offset, 1)

    local type = type_buf:uint()
    offset = offset+1
    local len_buf = buffer(offset, 2)
    local field_len = len_buf:uint()
    offset = offset+2

    local tree_buf = buffer(start_offset, len_buf:uint() + 3)
    local field_buf = buffer(offset, len_buf:uint())

    local fieldSubtree = subtree:add(ubntdisc_protocol, tree_buf(), get_field_description(type))
    fieldSubtree:add(pf.field_type,  type_buf):append_text(" (" .. (get_field_name(type)) .. ")")
    fieldSubtree:add(pf.field_length, len_buf)

    if type == 0x01 then
      fieldSubtree:add(pf.field_mac, field_buf(0, 6))
    elseif type == 0x02 then
      fieldSubtree:add(pf.field_mac, field_buf(0, 6))
      fieldSubtree:add(pf.field_ip, field_buf(6, 4))
    elseif type == 0x03 then
      -- firmwareversion
      fieldSubtree:add(pf.field_firmversion, field_buf(0, field_len))
    elseif type == 0x06 then
      -- username
      fieldSubtree:add(pf.field_username, field_buf(0, field_len))
    elseif type == 0x07 then
      -- salt
      fieldSubtree:add(pf.field_salt, field_buf(0, field_len))
    elseif type == 0x08 then
      -- rndchallenge
      fieldSubtree:add(pf.field_rndchallenge, field_buf(0, field_len))
    elseif type == 0x09 then
      -- challenge
      fieldSubtree:add(pf.field_challenge, field_buf(0, field_len))
    elseif type == 0x0A then
      -- Uptime
      fieldSubtree:add(pf.field_uptime, field_buf(0, 4))
    elseif type == 0x0B then
      -- Hostname
      fieldSubtree:add(pf.field_hostname, field_buf(0, field_len))
    elseif type == 0x0C then
      -- Platform
      fieldSubtree:add(pf.field_platform, field_buf(0, field_len))
    elseif type == 0x0D then
      -- ESSID
      fieldSubtree:add(pf.field_essid, field_buf(0, field_len))
    elseif type == 0x0E then
      -- WMode
      fieldSubtree:add(pf.field_wmode, field_buf(0, 1))
    elseif type == 0x0F then
      -- Webui
      fieldSubtree:add(pf.field_webui, field_buf(0, field_len))
    elseif type == 0x12 then
      -- Seq
      fieldSubtree:add(pf.field_seq, field_buf(0, 4))
    elseif type == 0x13 then
      -- Serial
      fieldSubtree:add(pf.field_serial, field_buf(0, 6))
    elseif type == 0x14 or type == 0x15 then
      -- Model
      fieldSubtree:add(pf.field_model, field_buf(0, field_len))
    elseif type == 0x16 then
      -- Version
      fieldSubtree:add(pf.field_version, field_buf(0, field_len))
    elseif type == 0x17 then
      -- Default
      fieldSubtree:add(pf.field_default, field_buf(0, 1))
    elseif type == 0x18 then
      -- Locating
      fieldSubtree:add(pf.field_locating, field_buf(0, 1))
    elseif type == 0x19 then
      -- dhcpclient
      fieldSubtree:add(pf.field_dhcpclient, field_buf(0, 1))
    elseif type == 0x1A then
      -- dhcpclientbound
      fieldSubtree:add(pf.field_dhcpclientbound, field_buf(0, 1))
    elseif type == 0x1B then
      -- reqversion
      fieldSubtree:add(pf.field_reqversion, field_buf(0, field_len))
    elseif type == 0x1C then
      -- sshdport
      fieldSubtree:add(pf.field_sshdport, field_buf(0, 2))
    else
      fieldSubtree:add(pf.field_unknowndata, field_buf(0, field_len))
    end

    offset = offset + field_len
  end

end

function get_field_name(opcode)
  local opcode_name = "Unknown"

      if opcode == 0x01 then field_name = "HardwareAddress"
  elseif opcode == 0x02 then field_name = "IPInfo"
  elseif opcode == 0x03 then field_name = "FirmwareVersion"
  elseif opcode == 0x04 then field_name = "Unknown"
  elseif opcode == 0x05 then field_name = "Unknown"
  elseif opcode == 0x06 then field_name = "Username"
  elseif opcode == 0x07 then field_name = "Salt"
  elseif opcode == 0x08 then field_name = "RndChallenge"
  elseif opcode == 0x09 then field_name = "Challenge"
  elseif opcode == 0x0A then field_name = "Uptime"
  elseif opcode == 0x0B then field_name = "Hostname"
  elseif opcode == 0x0C then field_name = "Platform"
  elseif opcode == 0x0D then field_name = "ESSID"
  elseif opcode == 0x0E then field_name = "WMode"
  elseif opcode == 0x0F then field_name = "WebUI"
  elseif opcode == 0x10 then field_name = "Unknown"
  elseif opcode == 0x11 then field_name = "Unknown"
  elseif opcode == 0x12 then field_name = "Sequence"
  elseif opcode == 0x13 then field_name = "Serial"
  elseif opcode == 0x14 then field_name = "Model"
  elseif opcode == 0x15 then field_name = "Model"
  elseif opcode == 0x16 then field_name = "Version"
  elseif opcode == 0x17 then field_name = "Default"
  elseif opcode == 0x18 then field_name = "Locating"
  elseif opcode == 0x19 then field_name = "DhcpClient"
  elseif opcode == 0x1A then field_name = "DhcpClientBound"
  elseif opcode == 0x1B then field_name = "ReqVersion"
  elseif opcode == 0x1C then field_name = "SshdPort"
  elseif opcode == 0x1D then field_name = "Unknown" end
  return field_name
end

function get_field_description(opcode)
  local opcode_name = "Unknown"

      if opcode == 0x01 then field_desc = "MAC Address"
  elseif opcode == 0x02 then field_desc = "IP/MAC Information"
  elseif opcode == 0x03 then field_desc = "Firmware Version"
  elseif opcode == 0x04 then field_desc = "Unknown"
  elseif opcode == 0x05 then field_desc = "Unknown"
  elseif opcode == 0x06 then field_desc = "Username"
  elseif opcode == 0x07 then field_desc = "Salt"
  elseif opcode == 0x08 then field_desc = "Rnd Challenge"
  elseif opcode == 0x09 then field_desc = "Challenge"
  elseif opcode == 0x0A then field_desc = "Uptime"
  elseif opcode == 0x0B then field_desc = "Hostname"
  elseif opcode == 0x0C then field_desc = "Platform"
  elseif opcode == 0x0D then field_desc = "ESSID"
  elseif opcode == 0x0E then field_desc = "WMode"
  elseif opcode == 0x0F then field_desc = "Web UI URL"
  elseif opcode == 0x10 then field_desc = "Unknown"
  elseif opcode == 0x11 then field_desc = "Unknown"
  elseif opcode == 0x12 then field_desc = "Sequence"
  elseif opcode == 0x13 then field_desc = "Serial"
  elseif opcode == 0x14 then field_desc = "Model Name"
  elseif opcode == 0x15 then field_desc = "Model Name"
  elseif opcode == 0x16 then field_desc = "Version"
  elseif opcode == 0x17 then field_desc = "Default"
  elseif opcode == 0x18 then field_desc = "Locating"
  elseif opcode == 0x19 then field_desc = "DHCP Client"
  elseif opcode == 0x1A then field_desc = "DHCP Client Bound"
  elseif opcode == 0x1B then field_desc = "Required Firmware Version"
  elseif opcode == 0x1C then field_desc = "SSHD Port"
  elseif opcode == 0x1D then field_desc = "Unknown" end
  return field_desc
end


local udp_port = DissectorTable.get("udp.port"):add(10001, ubntdisc_protocol)
