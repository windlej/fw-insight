# Adding a Vendor Parser

## Steps

1. **Create parser package**
   ```
   parsers/<vendor>/
   ├── __init__.py
   ├── parser.py
   ├── normalizer.py
   └── tests/
       ├── fixtures/
       └── test_parser.py
   ```

2. **Implement VendorParser interface**
   ```python
   from parsers.base import VendorParser, VendorAST, ParseError

   class MyVendorParser(VendorParser):
       VENDOR_ID = "myvendor"

       def parse(self, raw_config: str | bytes) -> VendorAST:
           # Parse raw config into vendor-specific AST
           # Raise ParseError on failures
           pass

       def normalize(self, ast: VendorAST) -> dict:
           # Convert AST to Session-compatible dict
           pass
   ```

3. **Register the parser**

   Add to `parsers/__init__.py`:
   ```python
   from parsers.<vendor> import MyVendorParser
   register_parser(MyVendorParser)
   ```

4. **Add test fixtures**

   Place at least 3 configs in `tests/fixtures/`:
   - Minimal (few rules, basic objects)
   - Medium (~25-50 rules, groups, zones)
   - Complex (60+ rules, nested groups, edge cases)

5. **Write tests**

   Test parsing, normalization, group resolution, vendor_raw preservation.

## Contracts

- `parse()` returns `VendorAST` or raises `ParseError`
- `normalize()` returns dict compatible with `Session.model_validate()`
- All entities must have `vendor_raw` populated
- Object references must be resolved (groups → members)
- `position` always set (1-indexed)
- `enabled` always boolean (unknown = true)
