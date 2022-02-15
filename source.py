import json
import difflib
import os


class ContractSource(object):

    def __init__(self, code=None) -> None:
        self.contracts = {}  # name => source
        if code:
            self.parse_source(code)

    def _normalize_src(self, src: str):
        try:
            if src.startswith("{"):
                tmp = src
                if src.startswith("{{"):
                    tmp = src.replace('{{', "{").replace("}}", '}')
                sources = json.loads(tmp)
                if "sources" in sources:
                    sources = sources["sources"]

                srcs = [sources[name]["content"] for name in sources]
                return '\n//////\n'.join(srcs)
        except Exception as e:
            print(e)

        return src

    def parse_source(self, code: str):
        """
        Split full source code into contracts code.
        Note this method may throw exceptions.
        """
        code = self._normalize_src(code)

        while True:

            # Find the line which starts with "contract"

            # TODO: library, abstract contract, interface ?
            if not code.startswith('contract'):
                i = code.find('\ncontract')
                if i == -1:
                    # Not contract here.
                    break
                code = code[i + 1:]  # skip \n

            # Find the end of contract.
            count = 0
            end = 0
            for i, c in enumerate(code):
                if c == '{':
                    count += 1

                if c == '}':
                    count -= 1
                    assert count >= 0, "Curly brackets do NOT match"
                    if count == 0:
                        end = i + 1  # skip }
                        break

            contract_code = code[: end]
            contract_name = contract_code[:100].split()[1]

            assert contract_name not in self.contracts, "Same contract name."

            self.contracts[contract_name] = contract_code

            code = code[end:]  # continue.

    def __diff_file(self, a, b, output_filename):
        d = difflib.HtmlDiff()
        buf = d.make_file(a.splitlines(), b.splitlines())
        open(output_filename + '.html', 'w').write(buf)
        print("Written to " + output_filename+'.html')

    def compare(self, other, output='diff'):

        if not os.path.isdir(output):
            os.makedirs(output)

        to_comp = other.contracts
        for name1, src1, in self.contracts.items():
            if name1 in to_comp:
                src2 = to_comp[name1]
                filename = name1 + '_same'
                self.__diff_file(src1, src2, os.path.join(output, filename))
            else:
                for name2, src2 in to_comp.items():
                    s = difflib.SequenceMatcher(None, src1, src2)
                    similarity = s.ratio()
                    if similarity > 0.1:
                        filename = "%s_%s_%0.2f" % (name1, name2, similarity)
                        self.__diff_file(src1, src2, os.path.join(output, filename))
