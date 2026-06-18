import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Dex Agent Operator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    getclass_parser = subparsers.add_parser("getclass", help="Get decompiled Java code for a class")
    getclass_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    getclass_parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=8,
        help="Number of inflate/search worker threads (default: 8)",
    )
    getclass_parser.add_argument("apk_path", help="Path to the APK or JAR file")
    getclass_parser.add_argument("clazz", help="Target class name (e.g. com.target.class or Lcom/target/class;)")
    
    return parser.parse_args()
