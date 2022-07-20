package main

type ListClientsResponse struct {
	Domain   string   `json:"domain,omitempty"`
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	ImageURL string   `json:"imageUrl,omitempty"`
	URL      string   `json:"url,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}
