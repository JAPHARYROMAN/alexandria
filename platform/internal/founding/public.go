package founding

import "errors"

// ValidatePublic checks the same rights and provenance rules at the receiving node.
func (p Replica) ValidatePublic() error {
	if !identifier.MatchString(p.Collection) {
		return errors.New("invalid collection")
	}
	r := Record{ID: p.ID, Collection: p.Collection, Title: p.Title, Language: p.Language, Credit: p.Credit, Description: p.Description, Origin: p.Origin, Rights: p.Rights, Body: p.Body}
	switch p.Rights {
	case "CC0-1.0":
		r.Mode = "open-data"
		r.Evidence = p.RightsURL
	case "link-only":
		if p.RightsURL != "" {
			return errors.New("unexpected rights field on link")
		}
		r.Mode = "external-link"
		r.Evidence = "Publisher link"
	default:
		return errors.New("material has no public permission")
	}
	return r.validate()
}
