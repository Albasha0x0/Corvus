-- Totals and labels for a small ledger.
local Ledger = {}
Ledger.__index = Ledger

function Ledger.new(name)
  return setmetatable({ name = name, entries = {} }, Ledger)
end

function Ledger:add(amount, note)
  self.entries[#self.entries + 1] = { amount = amount, note = note or "" }
end

function Ledger:total()
  local sum = 0
  for _, e in ipairs(self.entries) do sum = sum + e.amount end
  return sum
end

local function label(l, ...)
  local extra = select("#", ...)
  return string.format("%s: %.2f (%d extra)", l.name, l:total(), extra)
end

local book = Ledger.new("cash")
book:add(12.5, "paper")
book:add(3)
print(label(book), 2^53, -7, 0x7fffffff, true, nil)
return Ledger
