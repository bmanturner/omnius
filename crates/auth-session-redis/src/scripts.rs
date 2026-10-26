//! Lua scripts executed atomically by the session lifecycle index.

pub(crate) const PERMISSION_PROBE_SCRIPT: &str = r"
if redis.call('EXISTS', KEYS[1]) ~= 1 then return 0 end
if redis.call('TYPE', KEYS[2])['ok'] ~= 'none' then return 0 end
if redis.call('TYPE', KEYS[3])['ok'] ~= 'none' then return 0 end
redis.call('SET', KEYS[2], '0')
if redis.call('GET', KEYS[2]) ~= '0' then return 0 end
if redis.call('INCR', KEYS[2]) ~= 1 then return 0 end
if redis.call('EXPIRE', KEYS[2], 30) ~= 1 then return 0 end
if redis.call('TTL', KEYS[2]) <= 0 then return 0 end
if redis.call('PERSIST', KEYS[2]) ~= 1 then return 0 end
if redis.call('TTL', KEYS[2]) ~= -1 then return 0 end
redis.call('SADD', KEYS[3], ARGV[1])
if redis.call('SCARD', KEYS[3]) ~= 1 then return 0 end
if redis.call('SISMEMBER', KEYS[3], ARGV[1]) ~= 1 then return 0 end
if #redis.call('SMEMBERS', KEYS[3]) ~= 1 then return 0 end
redis.call('SREM', KEYS[3], ARGV[1])
redis.call('DEL', KEYS[2], KEYS[3])
return 1
";

pub(crate) const REGISTER_SCRIPT: &str = r"
local function valid_type(key, expected)
  local kind = redis.call('TYPE', key)['ok']
  return kind == 'none' or kind == expected
end
if not valid_type(KEYS[1], 'string') or
   not valid_type(KEYS[2], 'string') or
   not valid_type(KEYS[3], 'string') or
   not valid_type(KEYS[4], 'string') or
   not valid_type(KEYS[5], 'set') or
   not valid_type(KEYS[6], 'set') or
   not valid_type(KEYS[7], 'set') or
   not valid_type(KEYS[8], 'set') or
   not valid_type(KEYS[9], 'set') or
   not valid_type(KEYS[10], 'set') or
   not valid_type(KEYS[11], 'set') then
  redis.call('DEL', KEYS[1])
  return -4
end
local expected_subject = tonumber(ARGV[1])
local expected_device = tonumber(ARGV[2])
local expected_lineage = tonumber(ARGV[3])
local subject_epoch = tonumber(redis.call('GET', KEYS[2]) or '0')
local device_epoch = tonumber(redis.call('GET', KEYS[3]) or '0')
local lineage_epoch = tonumber(redis.call('GET', KEYS[4]) or '0')
if not expected_subject or expected_subject < 0 or
   not expected_device or expected_device < 0 or
   not expected_lineage or expected_lineage < 0 or
   not subject_epoch or not device_epoch or not lineage_epoch then
  redis.call('DEL', KEYS[1])
  return -4
end
if subject_epoch ~= expected_subject or
   device_epoch ~= expected_device or
   lineage_epoch ~= expected_lineage then
  redis.call('DEL', KEYS[1])
  return -1
end
if redis.call('EXISTS', KEYS[1]) ~= 1 then
  return -2
end
if (redis.call('SISMEMBER', KEYS[5], ARGV[5]) == 0 and redis.call('SCARD', KEYS[5]) >= tonumber(ARGV[12])) or
   (redis.call('SISMEMBER', KEYS[6], ARGV[4]) == 0 and redis.call('SCARD', KEYS[6]) >= tonumber(ARGV[13])) or
   (redis.call('SISMEMBER', KEYS[7], ARGV[6]) == 0 and redis.call('SCARD', KEYS[7]) >= tonumber(ARGV[14])) or
   (redis.call('SISMEMBER', KEYS[8], ARGV[7]) == 0 and redis.call('SCARD', KEYS[8]) >= tonumber(ARGV[15])) or
   (redis.call('SISMEMBER', KEYS[9], ARGV[9]) == 0 and redis.call('SCARD', KEYS[9]) >= tonumber(ARGV[16])) or
   (redis.call('SISMEMBER', KEYS[10], ARGV[10]) == 0 and redis.call('SCARD', KEYS[10]) >= tonumber(ARGV[17])) or
   (redis.call('SISMEMBER', KEYS[11], ARGV[11]) == 0 and redis.call('SCARD', KEYS[11]) >= tonumber(ARGV[18])) then
  redis.call('DEL', KEYS[1])
  return -3
end
redis.call('PERSIST', KEYS[2])
redis.call('PERSIST', KEYS[3])
redis.call('PERSIST', KEYS[4])
redis.call('SADD', KEYS[5], ARGV[5])
redis.call('SADD', KEYS[6], ARGV[4])
redis.call('SADD', KEYS[7], ARGV[6])
redis.call('SADD', KEYS[8], ARGV[7])
redis.call('SADD', KEYS[9], ARGV[9])
redis.call('SADD', KEYS[10], ARGV[10])
redis.call('SADD', KEYS[11], ARGV[11])
return 1
";
pub(crate) const ROTATION_CLAIM_SCRIPT: &str = r"
local function valid_type(key, expected)
  local kind = redis.call('TYPE', key)['ok']
  return kind == 'none' or kind == expected
end
local function retain_or_remove(index, catalog, token, epoch, ttl)
  if redis.call('SCARD', index) ~= 0 then return end
  redis.call('DEL', index)
  if redis.call('TTL', epoch) == -1 then redis.call('EXPIRE', epoch, ttl) end
  if redis.call('EXISTS', epoch) == 0 then redis.call('SREM', catalog, token) end
end
if not valid_type(KEYS[1], 'string') or
   not valid_type(KEYS[2], 'string') or
   not valid_type(KEYS[3], 'string') or
   not valid_type(KEYS[4], 'string') or
   not valid_type(KEYS[5], 'set') or
   not valid_type(KEYS[6], 'set') or
   not valid_type(KEYS[7], 'set') or
   not valid_type(KEYS[8], 'set') or
   not valid_type(KEYS[9], 'set') or
   not valid_type(KEYS[10], 'set') or
   not valid_type(KEYS[11], 'set') then return -4 end
local expected_subject = tonumber(ARGV[1])
local expected_device = tonumber(ARGV[2])
local expected_lineage = tonumber(ARGV[3])
local subject_epoch = tonumber(redis.call('GET', KEYS[2]) or '0')
local device_epoch = tonumber(redis.call('GET', KEYS[3]) or '0')
local lineage_epoch = tonumber(redis.call('GET', KEYS[4]) or '0')
if not expected_subject or expected_subject < 0 or
   not expected_device or expected_device < 0 or
   not expected_lineage or expected_lineage < 0 or
   not subject_epoch or not device_epoch or not lineage_epoch then return -4 end
if subject_epoch ~= expected_subject or
   device_epoch ~= expected_device or
   lineage_epoch ~= expected_lineage or
   redis.call('EXISTS', KEYS[1]) ~= 1 or
   redis.call('SISMEMBER', KEYS[5], ARGV[5]) ~= 1 or
   redis.call('SISMEMBER', KEYS[6], ARGV[4]) ~= 1 or
   redis.call('SISMEMBER', KEYS[7], ARGV[6]) ~= 1 or
   redis.call('SISMEMBER', KEYS[8], ARGV[7]) ~= 1 or
   redis.call('SISMEMBER', KEYS[9], ARGV[8]) ~= 1 or
   redis.call('SISMEMBER', KEYS[10], ARGV[9]) ~= 1 or
   redis.call('SISMEMBER', KEYS[11], ARGV[10]) ~= 1 then return -1 end
local claimed = redis.call('INCR', KEYS[4])
redis.call('EXPIRE', KEYS[4], tonumber(ARGV[11]))
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[5], ARGV[5])
redis.call('SREM', KEYS[6], ARGV[4])
redis.call('SREM', KEYS[7], ARGV[6])
redis.call('SREM', KEYS[8], ARGV[7])
retain_or_remove(KEYS[6], KEYS[9], ARGV[8], KEYS[2], tonumber(ARGV[11]))
retain_or_remove(KEYS[7], KEYS[10], ARGV[9], KEYS[3], tonumber(ARGV[11]))
retain_or_remove(KEYS[8], KEYS[11], ARGV[10], KEYS[4], tonumber(ARGV[11]))
return claimed
";

pub(crate) const VALIDATE_SCRIPT: &str = r"
local subject_epoch = tonumber(redis.call('GET', KEYS[2]) or '0')
local device_epoch = tonumber(redis.call('GET', KEYS[3]) or '0')
local lineage_epoch = tonumber(redis.call('GET', KEYS[4]) or '0')
if not subject_epoch or not device_epoch or not lineage_epoch then return -1 end
if subject_epoch ~= tonumber(ARGV[1]) or
   device_epoch ~= tonumber(ARGV[2]) or
   lineage_epoch ~= tonumber(ARGV[3]) then return 0 end
if redis.call('EXISTS', KEYS[1]) ~= 1 then return 0 end
if redis.call('SISMEMBER', KEYS[5], ARGV[5]) ~= 1 then return 0 end
if redis.call('SISMEMBER', KEYS[6], ARGV[4]) ~= 1 then return 0 end
if redis.call('SISMEMBER', KEYS[7], ARGV[6]) ~= 1 then return 0 end
if redis.call('SISMEMBER', KEYS[8], ARGV[7]) ~= 1 then return 0 end
return 1
";

pub(crate) const REMOVE_INDEX_SCRIPT: &str = r"
local function retain_or_remove(index, catalog, token, epoch, ttl)
  if redis.call('SCARD', index) ~= 0 then return end
  redis.call('DEL', index)
  if redis.call('TTL', epoch) == -1 then redis.call('EXPIRE', epoch, ttl) end
  if redis.call('EXISTS', epoch) == 0 then redis.call('SREM', catalog, token) end
end
redis.call('SREM', KEYS[1], ARGV[1])
redis.call('SREM', KEYS[2], ARGV[2])
redis.call('SREM', KEYS[3], ARGV[3])
redis.call('SREM', KEYS[4], ARGV[4])
retain_or_remove(KEYS[2], KEYS[5], ARGV[5], KEYS[8], tonumber(ARGV[8]))
retain_or_remove(KEYS[3], KEYS[6], ARGV[6], KEYS[9], tonumber(ARGV[8]))
retain_or_remove(KEYS[4], KEYS[7], ARGV[7], KEYS[10], tonumber(ARGV[8]))
return 1
";

pub(crate) const REVOKE_CURRENT_SCRIPT: &str = r"
local function valid_type(key, expected)
  local kind = redis.call('TYPE', key)['ok']
  return kind == 'none' or kind == expected
end
local function retain_or_remove(index, catalog, token, epoch, ttl)
  if redis.call('SCARD', index) ~= 0 then return end
  redis.call('DEL', index)
  if redis.call('TTL', epoch) == -1 then redis.call('EXPIRE', epoch, ttl) end
  if redis.call('EXISTS', epoch) == 0 then redis.call('SREM', catalog, token) end
end
if not valid_type(KEYS[1], 'string') or
   not valid_type(KEYS[2], 'string') or
   not valid_type(KEYS[3], 'set') or
   not valid_type(KEYS[4], 'set') or
   not valid_type(KEYS[5], 'set') or
   not valid_type(KEYS[6], 'set') or
   not valid_type(KEYS[7], 'set') or
   not valid_type(KEYS[8], 'set') or
   not valid_type(KEYS[9], 'string') then return -4 end
if redis.call('SCARD', KEYS[3]) > tonumber(ARGV[5]) or
   redis.call('SCARD', KEYS[8]) > tonumber(ARGV[6]) or
   (redis.call('SISMEMBER', KEYS[8], ARGV[3]) == 0 and
    redis.call('SCARD', KEYS[8]) >= tonumber(ARGV[6])) then return -3 end
local members = redis.call('SMEMBERS', KEYS[3])
for _, member in ipairs(members) do
  if string.len(member) <= 37 or string.sub(member, 37, 37) ~= ':' then return -4 end
  local device = string.sub(member, 1, 36)
  if not valid_type(ARGV[4] .. ARGV[1] .. ':' .. device, 'set') or
     not valid_type(ARGV[7] .. ARGV[1] .. ':' .. device, 'string') then return -4 end
end
redis.call('SADD', KEYS[8], ARGV[3])
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[8]))
local deleted = redis.call('DEL', KEYS[2])
for _, member in ipairs(members) do
  local device = string.sub(member, 1, 36)
  local raw = string.sub(member, 38)
  deleted = deleted + redis.call('DEL', raw)
  redis.call('SREM', KEYS[4], ARGV[1] .. ':' .. device .. ':' .. ARGV[2] .. ':' .. raw)
  redis.call('SREM', KEYS[5], device .. ':' .. ARGV[2] .. ':' .. raw)
  local device_key = ARGV[4] .. ARGV[1] .. ':' .. device
  local device_token = ARGV[1] .. ':' .. device
  local device_epoch = ARGV[7] .. device_token
  redis.call('SREM', device_key, ARGV[2] .. ':' .. raw)
  retain_or_remove(device_key, KEYS[7], device_token, device_epoch, tonumber(ARGV[8]))
end
redis.call('DEL', KEYS[3])
retain_or_remove(KEYS[5], KEYS[6], ARGV[1], KEYS[9], tonumber(ARGV[8]))
return deleted + 1
";

pub(crate) const REVOKE_DEVICE_SCRIPT: &str = r"
local function valid_type(key, expected)
  local kind = redis.call('TYPE', key)['ok']
  return kind == 'none' or kind == expected
end
local function retain_or_remove(index, catalog, token, epoch, ttl)
  if redis.call('SCARD', index) ~= 0 then return end
  redis.call('DEL', index)
  if redis.call('TTL', epoch) == -1 then redis.call('EXPIRE', epoch, ttl) end
  if redis.call('EXISTS', epoch) == 0 then redis.call('SREM', catalog, token) end
end
if not valid_type(KEYS[1], 'string') or
   not valid_type(KEYS[2], 'set') or
   not valid_type(KEYS[3], 'set') or
   not valid_type(KEYS[4], 'set') or
   not valid_type(KEYS[5], 'set') or
   not valid_type(KEYS[6], 'set') or
   not valid_type(KEYS[7], 'set') or
   not valid_type(KEYS[8], 'string') then return -4 end
if redis.call('SCARD', KEYS[2]) > tonumber(ARGV[5]) or
   redis.call('SCARD', KEYS[3]) > tonumber(ARGV[6]) or
   redis.call('SCARD', KEYS[6]) > tonumber(ARGV[7]) or
   (redis.call('SISMEMBER', KEYS[6], ARGV[3]) == 0 and
    redis.call('SCARD', KEYS[6]) >= tonumber(ARGV[7])) then return -3 end
local members = redis.call('SMEMBERS', KEYS[2])
for _, member in ipairs(members) do
  if string.len(member) <= 37 or string.sub(member, 37, 37) ~= ':' then return -4 end
  local lineage = string.sub(member, 1, 36)
  if not valid_type(ARGV[4] .. ARGV[2] .. ':' .. lineage, 'set') or
     not valid_type(ARGV[8] .. ARGV[2] .. ':' .. lineage, 'string') then return -4 end
end
redis.call('SADD', KEYS[6], ARGV[3])
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[9]))
local deleted = 0
for _, member in ipairs(members) do
  local lineage = string.sub(member, 1, 36)
  local raw = string.sub(member, 38)
  deleted = deleted + redis.call('DEL', raw)
  redis.call('SREM', KEYS[3], ARGV[1] .. ':' .. lineage .. ':' .. raw)
  redis.call('SREM', KEYS[4], ARGV[2] .. ':' .. ARGV[1] .. ':' .. lineage .. ':' .. raw)
  local lineage_token = ARGV[2] .. ':' .. lineage
  local lineage_key = ARGV[4] .. lineage_token
  local lineage_epoch = ARGV[8] .. lineage_token
  redis.call('SREM', lineage_key, ARGV[1] .. ':' .. raw)
  retain_or_remove(lineage_key, KEYS[7], lineage_token, lineage_epoch, tonumber(ARGV[9]))
end
redis.call('DEL', KEYS[2])
retain_or_remove(KEYS[3], KEYS[5], ARGV[2], KEYS[8], tonumber(ARGV[9]))
return deleted
";

pub(crate) const REVOKE_ALL_SCRIPT: &str = r"
local function valid_type(key, expected)
  local kind = redis.call('TYPE', key)['ok']
  return kind == 'none' or kind == expected
end
if not valid_type(KEYS[1], 'string') or
   not valid_type(KEYS[2], 'set') or
   not valid_type(KEYS[3], 'set') or
   not valid_type(KEYS[4], 'set') or
   not valid_type(KEYS[5], 'set') or
   not valid_type(KEYS[6], 'set') then return -4 end
if redis.call('SCARD', KEYS[2]) > tonumber(ARGV[4]) or
   redis.call('SCARD', KEYS[4]) > tonumber(ARGV[5]) or
   redis.call('SCARD', KEYS[5]) > tonumber(ARGV[6]) or
   redis.call('SCARD', KEYS[6]) > tonumber(ARGV[7]) or
   (redis.call('SISMEMBER', KEYS[4], ARGV[1]) == 0 and
    redis.call('SCARD', KEYS[4]) >= tonumber(ARGV[5])) then return -3 end
local members = redis.call('SMEMBERS', KEYS[2])
local devices = redis.call('SMEMBERS', KEYS[5])
local lineages = redis.call('SMEMBERS', KEYS[6])
for _, member in ipairs(members) do
  if string.len(member) <= 74 or
     string.sub(member, 37, 37) ~= ':' or
     string.sub(member, 74, 74) ~= ':' then return -4 end
  local device = string.sub(member, 1, 36)
  local lineage = string.sub(member, 38, 73)
  if not valid_type(ARGV[2] .. ARGV[1] .. ':' .. device, 'set') or
     not valid_type(ARGV[3] .. ARGV[1] .. ':' .. lineage, 'set') or
     not valid_type(ARGV[8] .. ARGV[1] .. ':' .. device, 'string') or
     not valid_type(ARGV[9] .. ARGV[1] .. ':' .. lineage, 'string') then return -4 end
end
local prefix = ARGV[1] .. ':'
for _, token in ipairs(devices) do
  if string.sub(token, 1, string.len(prefix)) == prefix then
    if not valid_type(ARGV[2] .. token, 'set') or
       not valid_type(ARGV[8] .. token, 'string') then return -4 end
  end
end
for _, token in ipairs(lineages) do
  if string.sub(token, 1, string.len(prefix)) == prefix then
    if not valid_type(ARGV[3] .. token, 'set') or
       not valid_type(ARGV[9] .. token, 'string') then return -4 end
  end
end
redis.call('SADD', KEYS[4], ARGV[1])
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[10]))
local deleted = 0
for _, member in ipairs(members) do
  local device = string.sub(member, 1, 36)
  local lineage = string.sub(member, 38, 73)
  local raw = string.sub(member, 75)
  deleted = deleted + redis.call('DEL', raw)
  redis.call('SREM', KEYS[3], ARGV[1] .. ':' .. device .. ':' .. lineage .. ':' .. raw)
end
for _, token in ipairs(devices) do
  if string.sub(token, 1, string.len(prefix)) == prefix then
    redis.call('DEL', ARGV[2] .. token, ARGV[8] .. token)
    redis.call('SREM', KEYS[5], token)
  end
end
for _, token in ipairs(lineages) do
  if string.sub(token, 1, string.len(prefix)) == prefix then
    redis.call('DEL', ARGV[3] .. token, ARGV[9] .. token)
    redis.call('SREM', KEYS[6], token)
  end
end
redis.call('DEL', KEYS[2])
return deleted
";

pub(crate) const PRUNE_MEMBER_SCRIPT: &str = r"
redis.call('SREM', KEYS[1], ARGV[1])
if redis.call('SCARD', KEYS[1]) == 0 then
  redis.call('DEL', KEYS[1])
  if redis.call('TTL', KEYS[3]) == -1 then
    redis.call('EXPIRE', KEYS[3], tonumber(ARGV[3]))
  end
  if redis.call('EXISTS', KEYS[3]) == 0 then
    redis.call('DEL', KEYS[3])
    redis.call('SREM', KEYS[2], ARGV[2])
  end
end
return 1
";
