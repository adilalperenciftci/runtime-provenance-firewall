package rpf

import "errors"

const LocalBuildType = "https://github.com/adilalperenciftci/runtime-provenance-firewall/build-types/local-fixture/v0.1"
const LocalBuilderID = "https://github.com/adilalperenciftci/runtime-provenance-firewall/builders/local-fixture/v0.1"

func CreateLocalFixtureProvenance(artifactName string, artifact []byte, events []Event, repository, revision string) (Statement, error) {
	if artifactName == "" || len(artifact) == 0 || len(events) == 0 || repository == "" || revision == "" {
		return Statement{}, errors.New("local provenance inputs are incomplete")
	}
	artifactHash := Digest(artifact)
	if err := verifyArtifactObservation(events, artifactHash); err != nil {
		return Statement{}, err
	}
	first := events[0]
	last := events[len(events)-1]
	if first.Build.Source != (SourceIdentity{Repository: repository, Revision: revision}) {
		return Statement{}, errors.New("local provenance source differs from runtime evidence")
	}
	identity := Correlation{
		BuildID:     first.Build.BuildID,
		BuilderID:   LocalBuilderID,
		RunIdentity: RunIdentity{Provider: "local", RunID: first.Build.RunID, Attempt: 1},
		Source:      SourceIdentity{Repository: repository, Revision: revision},
	}
	identityMap, err := toMap(identity)
	if err != nil {
		return Statement{}, err
	}
	return Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: artifactName, Digest: map[string]string{"sha256": artifactHash}}},
		PredicateType: SLSAPredicate,
		Predicate: map[string]any{
			"buildDefinition": map[string]any{
				"buildType":            LocalBuildType,
				"externalParameters":   map[string]any{"repository": repository, "revision": revision},
				"internalParameters":   map[string]any{BuildIdentityKey: identityMap},
				"resolvedDependencies": []any{map[string]any{"uri": repository, "digest": map[string]any{"gitCommit": revision}}},
			},
			"runDetails": map[string]any{
				"builder":  map[string]any{"id": LocalBuilderID},
				"metadata": map[string]any{"invocationId": first.Build.RunID, "startedOn": first.ObservedAt, "finishedOn": last.ObservedAt},
			},
		},
	}, nil
}
