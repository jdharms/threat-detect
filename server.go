package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jdharms/threat-detect/internal/auth"
	"github.com/jdharms/threat-detect/internal/db"
	"github.com/jdharms/threat-detect/internal/dnsbl"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"

	"github.com/jdharms/threat-detect/graph"
	"github.com/jdharms/threat-detect/graph/generated"
)

const defaultPort = "8080"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	dbClient, err := db.NewClient("./data.db")
	if err != nil {
		log.Fatal(fmt.Sprintf("could not open database: %s", err.Error()))
	}
	defer dbClient.Close()

	blClient := dnsbl.SpamhausClient{}

	resolver := &graph.Resolver{
		Adder:  dbClient,
		Getter: dbClient,
		DNSBL:  blClient,
	}

	srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: resolver}))

	http.Handle("/", playground.Handler("GraphQL playground", "/graphql"))
	http.Handle("/graphql", auth.NewBasicAuth(auth.NewMapValidator(map[string]string{"secureworks": "supersecret"}))(srv))

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
