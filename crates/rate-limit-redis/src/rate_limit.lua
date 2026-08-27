-- omnius-rate-limit-redis/v1
-- KEYS[1]: bounded provider state key
-- ARGV: algorithm, limit/rate, period_us, burst, cost, max_state_ttl_us
local key_type = redis.call('TYPE', KEYS[1])
if type(key_type) == 'table' then
    key_type = key_type['ok']
end
if key_type ~= 'none' and key_type ~= 'hash' then
    return redis.error_reply('OMNIUS_RATE_LIMIT_INVALID_STATE')
end

local algorithm = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local period = tonumber(ARGV[3])
local burst = tonumber(ARGV[4])
local cost = tonumber(ARGV[5])
local max_state_ttl = tonumber(ARGV[6])
if not algorithm or not limit or not period or not burst or not cost or not max_state_ttl
    or algorithm % 1 ~= 0 or limit % 1 ~= 0 or period % 1 ~= 0
    or burst % 1 ~= 0 or cost % 1 ~= 0 or max_state_ttl % 1 ~= 0
    or algorithm < 1 or algorithm > 3 or limit < 1 or period < 1
    or burst < 1 or cost < 1 or max_state_ttl < 1 then
    return redis.error_reply('OMNIUS_RATE_LIMIT_INVALID_ARGUMENT')
end

local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) * 1000000 + tonumber(now_parts[2])

local function read_integer(field)
    local value = redis.call('HGET', KEYS[1], field)
    if value == false then
        return nil
    end
    local parsed = tonumber(value)
    if not parsed or parsed < 0 or parsed % 1 ~= 0 then
        return false
    end
    return parsed
end

local function invalid_state()
    return redis.error_reply('OMNIUS_RATE_LIMIT_INVALID_STATE')
end

local function ttl_millis(microseconds)
    return math.max(1, math.floor((microseconds + 999) / 1000))
end

if algorithm == 1 then
    local window = math.floor(now / period)
    local stored_window = read_integer('window')
    local count = read_integer('count')
    if stored_window == false or count == false
        or (stored_window == nil and count ~= nil)
        or (stored_window ~= nil and count == nil) then
        return invalid_state()
    end
    if stored_window ~= nil and (stored_window > window or count > limit) then
        return invalid_state()
    end
    if stored_window == nil or stored_window ~= window then
        stored_window = window
        count = 0
    end

    local allowed = 0
    if count + cost <= limit then
        count = count + cost
        allowed = 1
    end
    redis.call('HSET', KEYS[1], 'window', stored_window, 'count', count)
    local reset_us = (window + 1) * period - now
    redis.call('PEXPIRE', KEYS[1], ttl_millis(reset_us))
    local remaining = math.max(0, limit - count)
    local retry_us = 0
    if allowed == 0 then
        retry_us = reset_us
    end
    return {allowed, remaining, math.floor((retry_us + 999) / 1000), ttl_millis(reset_us)}
end

if algorithm == 2 then
    local window = math.floor(now / period)
    local stored_window = read_integer('window')
    local current = read_integer('current')
    local previous = read_integer('previous')
    local absent = stored_window == nil and current == nil and previous == nil
    local partial = stored_window == nil or current == nil or previous == nil
    if stored_window == false or current == false or previous == false
        or (not absent and partial)
        or (not absent and (current > limit or previous > limit)) then
        return invalid_state()
    end
    if absent then
        stored_window = window
        current = 0
        previous = 0
    elseif stored_window > window then
        return invalid_state()
    elseif stored_window < window then
        if window - stored_window == 1 then
            previous = current
        else
            previous = 0
        end
        current = 0
        stored_window = window
    end

    local elapsed = now - window * period
    local weighted = current * period + previous * (period - elapsed)
    local candidate = weighted + cost * period
    local allowed = 0
    if candidate <= limit * period then
        current = current + cost
        weighted = candidate
        allowed = 1
    end
    redis.call(
        'HSET', KEYS[1],
        'window', stored_window,
        'current', current,
        'previous', previous
    )
    local state_ttl_us = 2 * period - elapsed
    redis.call('PEXPIRE', KEYS[1], ttl_millis(state_ttl_us))

    local remaining = math.max(0, math.floor((limit * period - weighted) / period))
    local retry_us = 0
    if allowed == 0 then
        local excess = candidate - limit * period
        local until_boundary = period - elapsed
        if previous > 0 and math.ceil(excess / previous) <= until_boundary then
            retry_us = math.ceil(excess / previous)
        elseif current > 0 then
            local next_excess = math.max(0, current + cost - limit) * period
            retry_us = until_boundary + math.ceil(next_excess / current)
        else
            retry_us = until_boundary
        end
    end
    return {allowed, remaining, math.floor((retry_us + 999) / 1000), ttl_millis(state_ttl_us)}
end

local interval = math.ceil(period / limit)
local stored_tat = read_integer('tat')
if stored_tat == false then
    return invalid_state()
end
if stored_tat ~= nil and stored_tat - now > max_state_ttl then
    return invalid_state()
end
local tat = stored_tat or now
if tat < now then
    tat = now
end
local candidate_tat = tat + cost * interval
if candidate_tat - now > max_state_ttl then
    return invalid_state()
end
local allow_at = candidate_tat - burst * interval
if allow_at <= now then
    redis.call('HSET', KEYS[1], 'tat', candidate_tat)
    local reset_us = math.max(interval, candidate_tat - now)
    redis.call('PEXPIRE', KEYS[1], ttl_millis(reset_us))
    local remaining = math.max(
        0,
        math.floor((burst * interval - (candidate_tat - now)) / interval)
    )
    return {1, remaining, 0, ttl_millis(reset_us)}
end

local retry_us = allow_at - now
local reset_us = math.max(interval, tat - now)
redis.call('PEXPIRE', KEYS[1], ttl_millis(reset_us))
local remaining = math.max(0, math.floor((burst * interval - (tat - now)) / interval))
return {0, remaining, ttl_millis(retry_us), ttl_millis(reset_us)}
