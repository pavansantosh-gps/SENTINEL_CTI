from database import check_connection, get_database_stats, close_connection


print("=" * 60)
print("SENTINEL CTI — DATABASE CONNECTION TEST")
print("=" * 60)

if check_connection():
    print("[OK] MongoDB connection successful")
else:
    print("[ERROR] MongoDB connection failed")

stats = get_database_stats()

print("\nDatabase statistics:")
for collection, count in stats.items():
    print(f"{collection:20} : {count}")

close_connection()
print("\n[OK] Connection closed")