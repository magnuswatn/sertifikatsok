import React, { Component } from 'react';
import PropTypes from 'prop-types';
import M from 'materialize-css';

export class SearchForm extends Component {
    constructor(props) {
        super(props);
        this.ref = React.createRef();
    }

    componentDidMount() {
        this.self = M.Autocomplete.init(this.ref.current, {
            'limit': 20,
            'onAutocomplete': () => this.handleAutocomplete(),
        })
    }

    componentDidUpdate() {
        this.self.updateData(this.props.data);
        this.self.open();
        this.ref.current.focus();
    }

    componentWillUnmount() {
        this.self.destroy();
        this.self = null;
    }

    handleAutocomplete() {
        this.props.onAutocomplete(this.ref.current.value)
        this.self.close();
    }

    handleKeyPress(e) {
        if (e.key === 'Enter') {
            this.props.onEnter();
        }
    }

    render() {
        return (
            <div className="row">
                <div className="col s12">
                    <div className="row">
                        <div className="input-field col s12">
                            <input
                                ref={this.ref}
                                type="text"
                                autoFocus
                                onChange={() => this.props.onChange(this.ref.current.value)}
                                value={this.props.inputText}
                                onKeyDown={(e) => this.handleKeyPress(e)}
                            />
                            <label htmlFor="autocomplete-input">
                                <i className="material-icons">search</i>
                                {this.props.labelText}
                            </label>
                        </div>
                    </div>
                </div>
            </div>
        )
    }
}

SearchForm.propTypes = {
    labelText: PropTypes.string,
    inputText: PropTypes.string,
    onAutocomplete: PropTypes.func,
    onChange: PropTypes.func,
    onEnter: PropTypes.func,
    data: PropTypes.object,
}
