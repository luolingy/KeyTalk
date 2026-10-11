p = r"internal\session\session.go"
s = open(p, encoding="utf-8").read()
i = s.find('func (m *Manager) identifySender')
end = s.find('\n}\n', i)
print(s[i:end+3])
