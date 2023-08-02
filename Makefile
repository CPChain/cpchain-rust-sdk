
cloc:
	@gocloc --not-match-d="target" .

package:
	@cargo package

publish:
	@cargo publish --registry crates-io
